%%% @author Leonardo Rossi <leonardo.rossi@studenti.unipr.it>
%%% @copyright (C) 2015 Leonardo Rossi
%%%
%%% This software is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This software is distributed in the hope that it will be useful, but
%%% WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this software; if not, write to the Free Software Foundation,
%%% Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
%%%
%%% @doc This module define a authentication server: a process that wait
%%%      action/auth from worker or client.
%%%      It contains all the accounting, authorization and authentication
%%%      logic (AAA server).
%%%      It can be implemented e.g. as a oauth server.
%%%      The action that it should be satisfy is:
%%%        - register client
%%%        - get new access_token
%%%        - check a access token.
%%%      A tipical use case is a request from a worker to check if a access
%%%      token can execute a specific action on a specific set of data.
%%% @end

-module(oauth2_backend_mongopool).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-behaviour(oauth2_backend).

%%% OAuth2 backend functionality
-export([associate_access_code/3,
         associate_access_token/3,
         associate_refresh_token/3,
         authenticate_client/2,
         authenticate_user/2,
         get_client_identity/2,
         resolve_access_code/2,
         resolve_access_token/2,
         resolve_refresh_token/2,
         revoke_access_code/2,
         revoke_access_token/2,
         revoke_refresh_token/2,
         verify_client_scope/3,
         verify_redirection_uri/3,
         verify_resowner_scope/3,
         verify_scope/3
        ]).

%%% Tables
-define(ACCESS_CODE_TABLE, access_codes).
-define(ACCESS_TOKEN_TABLE, access_tokens).
-define(REFRESH_TOKEN_TABLE, refresh_tokens).

%%% Macros ===========================================================
-define(BACKEND, (oauth2_mongopool_config:backend())).

%%%_ * Types -----------------------------------------------------------

-type appctx()   :: oauth2_mongopool:appctx().
-type user()     :: oauth2:user().
-type client()   :: oauth2:client().
-type token()    :: oauth2:token().
-type grantctx() :: oauth2:grantctx().
-type scope()    :: oauth2:scope().

% API implementation

%%% Oauth2 Backend API implementation

-spec authenticate_user(user(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound | badpass}.
authenticate_user({UserId, Password}, AppCtx) ->
  case ?BACKEND:authenticate_user(
          UserId, Password, maps:get(backendctx, AppCtx)) of
    {error, ErrorType} -> {error, ErrorType};
    {ok, {_BackendCtx, User}} -> {ok, {AppCtx, User}}
  end.

-spec authenticate_client(client(), appctx()) ->
  {ok, {appctx(), client()}} | {error, notfound | badsecret}.
authenticate_client({ClientId, ClientSecret}, AppCtx) ->
  case ?BACKEND:authenticate_client(
          ClientId, ClientSecret, maps:get(backendctx, AppCtx)) of
    {error, ErrorType} -> {error, ErrorType};
    {ok, {_BackendCtx, Client}} -> {ok, {AppCtx, Client}}
  end.

-spec associate_refresh_token(token(), grantctx(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
associate_refresh_token(Token, Context, #{pool := Pool}=AppCtx) ->
  create(Pool, ?REFRESH_TOKEN_TABLE, Token, Context),
  {ok, AppCtx}.

-spec associate_access_code(token(), grantctx(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
associate_access_code(Token, Context, #{pool := Pool}=AppCtx) ->
  create(Pool, ?ACCESS_CODE_TABLE, Token, Context),
  {ok, AppCtx}.

-spec associate_access_token(token(), grantctx(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
associate_access_token(Token, Context, #{pool := Pool}=AppCtx) ->
  create(Pool, ?ACCESS_TOKEN_TABLE, Token, Context),
  {ok, AppCtx}.

-spec resolve_refresh_token(token(), appctx()) ->
  {ok, {appctx(), grantctx()}} | {error, notfound}.
resolve_refresh_token(Token, AppCtx) ->
  get(?REFRESH_TOKEN_TABLE, Token, AppCtx).

-spec resolve_access_code(token(), appctx()) ->
  {ok, {appctx(), grantctx()}} | {error, notfound}.
resolve_access_code(Token, AppCtx) ->
  get(?ACCESS_CODE_TABLE, Token, AppCtx).

-spec resolve_access_token(token(), appctx()) ->
  {ok, {appctx(), grantctx()}} | {error, notfound}.
resolve_access_token(Token, AppCtx) ->
  get(?ACCESS_TOKEN_TABLE, Token, AppCtx).

-spec revoke_refresh_token(token(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
revoke_refresh_token(Token, #{pool := Pool}=AppCtx) ->
  delete(Pool, ?REFRESH_TOKEN_TABLE, Token),
  {ok, AppCtx}.

-spec revoke_access_code(token(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
revoke_access_code(Token, #{pool := Pool}=AppCtx) ->
  delete(Pool, ?ACCESS_CODE_TABLE, Token),
  {ok, AppCtx}.

-spec revoke_access_token(token(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
revoke_access_token(Token, #{pool := Pool}=AppCtx) ->
  delete(Pool, ?ACCESS_TOKEN_TABLE, Token),
  {ok, AppCtx}.

-spec get_client_identity(client(), appctx()) ->
  {ok, {appctx(), client()}} | {error, notfound | badsecret}.
get_client_identity(ClientId, AppCtx) ->
  case ?BACKEND:get_client(ClientId, maps:get(backendctx, AppCtx)) of
    {error, ErrorType} -> {error, ErrorType};
    {ok, {_BackendCtx, Client}} -> {ok, {AppCtx, Client}}
  end.

-spec verify_redirection_uri(client(), binary(), appctx()) ->
  {ok, appctx()} | {error, notfound | baduri}.
verify_redirection_uri(
  #{<<"redirect_uri">> := ClientUri}, ClientUri, AppCtx) ->
  {ok, AppCtx};
verify_redirection_uri(
  #{<<"redirect_uri">> := _WrongUri}, _ClientUri, _AppCtx) ->
  {error, baduri}.

-spec verify_client_scope(client(), scope(), appctx()) ->
  {ok, {appctx(), scope()}} | {error, notfound | badscope}.
verify_client_scope(#{<<"scope">> := RegisteredScope}, Scope, AppCtx) ->
  verify_scope(RegisteredScope, Scope, AppCtx).

-spec verify_resowner_scope(term(), scope(), appctx()) ->
  {ok, {appctx(), scope()}} | {error, notfound | badscope}.
verify_resowner_scope(#{<<"scope">> := RegisteredScope}, Scope, AppCtx) ->
  verify_scope(RegisteredScope, Scope, AppCtx).

-spec verify_scope(scope(), scope(), appctx()) ->
  {ok, {appctx(), scope()}} | {error, notfound | badscope}.
verify_scope(_RegisteredScope, undefined, _AppCtx) ->
  {error, badscope};
verify_scope(_RegisteredScope, [], _AppCtx) ->
  {error, badscope};
verify_scope([], _Scope, _AppCtx) ->
  {error, badscope};
verify_scope(RegisteredScope, Scope, AppCtx) ->
  FQScopes = oauth2_scope_strategy_fq:explode(Scope),
  case oauth2_scope_strategy_fq:verify(
         FQScopes,
         oauth2_scope_strategy_fq:explode(RegisteredScope)) of
    true -> {ok, {AppCtx, oauth2_scope_strategy_fq:implode(FQScopes)}};
    false -> {error, badscope}
  end.

%% Private functions

-spec create(atom(), atom(), token(), grantctx()) -> ok.
create(Pool, Table, Token, Context) ->
  mongopool_app:insert(
    Pool, Table, #{<<"_id">> => Token,
                   <<"grant">> => maps:from_list(Context)}).

-spec delete(atom(), atom(), token()) -> ok.
delete(Pool, Table, Token) ->
  mongopool_app:delete(Pool, Table, #{<<"_id">> => Token}).

-spec get(atom(), token(), appctx()) ->
    {ok, {appctx(), grantctx()}} | {error, notfound}.
get(Table, Token, #{pool := Pool}=AppCtx) ->
  adapt_get(
    mongopool_app:find_one(Pool, Table, #{<<"_id">> => Token}), AppCtx).

-spec adapt_get(map(), appctx()) ->
    {ok, {appctx(), grantctx()}} | {error, notfound}.
adapt_get(#{<<"_id">> := _Token, <<"grant">> := Grant}, AppCtx) ->
  {ok, {AppCtx, maps:to_list(Grant)}};
adapt_get(_, _) -> {error, notfound}.

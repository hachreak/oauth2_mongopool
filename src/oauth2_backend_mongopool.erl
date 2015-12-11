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

%%% API
-export([
         add_client/5,
         add_resowner/4,
         add_resowner/5,
         add_resowner_scope/3,
         remove_resowner_scope/3,
         get_resowner_scope/2,
         get_client/2,
         get_resowner/2,
         delete_client/1,
         delete_resowner/1
        ]).

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
         verify_scope/3,
         is_authorized/3
        ]).

%%% Tables
-define(USER_TABLE, users).
-define(CLIENT_TABLE, clients).
-define(ACCESS_CODE_TABLE, access_codes).
-define(ACCESS_TOKEN_TABLE, access_tokens).
-define(REFRESH_TOKEN_TABLE, refresh_tokens).

%%%_ * Types -----------------------------------------------------------

-type user()     :: oauth2:user().
-type appctx()   :: oauth2:appctx().
-type client()   :: oauth2:client().
-type token()    :: oauth2:token().
-type grantctx() :: oauth2:grantctx().
-type scope()    :: oauth2:scope().

% API implementation

%% @doc check object authorization
%%      if auth fail, then raise an exception not_authorized else return ok.
-spec is_authorized(oauth2:auth(), fun((grantctx()) -> scope()), appctx()) ->
  list() | no_return().
% TODO can be improved?
is_authorized(AccessToken, GetObjectScope, AppCtx)
  when is_function(GetObjectScope) ->
  case oauth2:verify_access_token(AccessToken, AppCtx) of
    {ok, {_AppCtx, GrantCtx}} ->
      case lists:keyfind(<<"scope">>, 1, GrantCtx) of
        {<<"scope">>, PermittedScope} ->
          case verify_scope(
                 PermittedScope, GetObjectScope(GrantCtx), undefined) of
            {ok, {_AppCtxt, _VerifiedScope}} -> GrantCtx;
            {error, _ErrorType} -> throw(not_authorized)
          end;
        false -> throw(not_authorized)
      end;
    {error, _ErrorType} -> throw(not_authorized)
  end.

get_resowner_scope(Username, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?USER_TABLE, #{<<"_id">> => Username}) of
    #{<<"scope">> := Scope} -> {ok, {AppCtx, Scope}};
    #{} -> throw(not_found)
  end.

% @doc add a new scope to user.
add_resowner_scope(Username, Scope, AppCtx) when is_binary(Scope) ->
  add_resowner_scope(Username, [Scope], AppCtx);
add_resowner_scope(Username, Scope, #{pool := Pool}=AppCtx)
  when is_list(Scope) ->
  {ok, #{<<"scope">> := CurrentScope}} = get_resowner(Username, AppCtx),
  MergedScopes = lists:umerge(CurrentScope, Scope),
  mongopool_app:update(Pool, ?USER_TABLE,
                       #{<<"_id">> => Username}, {<<"$set">>, MergedScopes}).

% @doc remove a scope from user.
remove_resowner_scope(Username, Scope, AppCtx) when is_binary(Scope) ->
  remove_resowner_scope(Username, [Scope], AppCtx);
remove_resowner_scope(Username, Scope, #{pool := Pool}=AppCtx)
  when is_list(Scope) ->
  {ok, #{<<"scope">> := CurrentScope}} = get_resowner(Username, AppCtx),
  RemovedScopes = lists:subtract(CurrentScope, Scope),
  mongopool_app:update(Pool, ?USER_TABLE,
                       #{<<"_id">> => Username}, {<<"$set">>, RemovedScopes}).


-spec add_client(binary(), binary(), binary(), oauth2:scope(), appctx()) ->
  {ok, appctx()} | {error, term()}.
add_client(Id, Secret, RedirectUri, Scope, #{pool := Pool}=AppCtx) ->
  mongopool_app:insert(Pool, ?CLIENT_TABLE, #{
                    <<"_id">> => Id,
                    % TODO remove client_id?
                    <<"client_id">> => Id,
                    <<"client_secret">> => Secret,
                    <<"redirect_uri">> => RedirectUri,
                    <<"scope">> => Scope
                   }),
  {ok, AppCtx}.

-spec add_resowner(binary(), binary(), binary(), appctx()) ->
  {ok, appctx()} | {error, term()}.
add_resowner(Username, Password, Email, AppCtx) ->
  add_resowner(Username, Password, Email,
               [<< <<"users.">>/binary, Username/binary >>], AppCtx).

-spec add_resowner(binary(), binary(), binary(), oauth2:scope(), appctx()) ->
  {ok, appctx()} | {error, term()}.
add_resowner(Username, Password, Email, Scope, #{pool := Pool}=AppCtx) ->
  {ok, {Cctx, _Pctx}} = esh_worker_user_confirm:init(),
  mongopool_app:insert(Pool, ?USER_TABLE, #{
                  <<"_id">> => Username,
                  <<"username">> => Username,
                  <<"password">> => Password,
                  <<"email">> => Email,
                  <<"status">> => <<"register">>,
                  <<"_ctx">> => Cctx,
                  <<"scope">> => Scope}),
  % FIXME
  % esh_worker_user_confirm:register_user(Username, Username, Email,
                                        % {Cctx, _Pctx}),
  {ok, AppCtx}.

-spec delete_resowner(Username) -> ok when
    Username :: binary().
delete_resowner(Username) ->
  mongopool_app:delete(eshpool, ?USER_TABLE, #{<<"_id">> => Username}).

-spec delete_client(Id) -> ok when
    Id :: binary().
delete_client(Id) ->
  mongopool_app:delete(eshpool, ?CLIENT_TABLE, #{<<"_id">> => Id}).

get_resowner(Username, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?USER_TABLE, #{<<"_id">> => Username}) of
    #{<<"_id">> := Username}=User -> {ok, {AppCtx, User}};
    #{} -> throw(notfound)
  end.

get_client(ClientId, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?CLIENT_TABLE, #{<<"_id">> => ClientId}) of
    #{<<"_id">> := ClientId}=Client -> {ok, {AppCtx, Client}};
    #{} -> {error, notfound}
  end.

%%% Oauth2 Backend API implementation

-spec authenticate_user(user(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound | badpass}.
authenticate_user({UserId, Password}, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?USER_TABLE, #{<<"_id">> => UserId}) of
    #{<<"password">> := Password} = Identity ->
      {ok, {AppCtx, Identity#{<<"password">> := undefined}}};
    #{<<"password">> := _WrongPassword} -> {error, badpass};
    #{} -> {error, notfound}
  end.

-spec authenticate_client(client(), appctx()) ->
  {ok, {appctx(), client()}} | {error, notfound | badsecret}.
authenticate_client({ClientId, ClientSecret}, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?CLIENT_TABLE, #{<<"_id">> => ClientId}) of
    #{<<"client_secret">> := ClientSecret}=Identity ->
      {ok, {AppCtx, Identity#{<<"client_secret">> := undefined}}};
    #{<<"client_secret">> := _WrongClientSecret} -> {error, badsecret};
    #{} -> {error, notfound}
  end.

-spec associate_refresh_token(token(), grantctx(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
associate_refresh_token(RefreshToken, Context, #{pool := Pool}=AppCtx) ->
  mongopool_app:insert(
    Pool, ?REFRESH_TOKEN_TABLE,
    #{<<"_id">> => RefreshToken, <<"token">> => RefreshToken,
      <<"grant">> => Context}),
  {ok, AppCtx}.

-spec associate_access_code(token(), grantctx(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
associate_access_code(AccessCode, Context, #{pool := Pool}=AppCtx) ->
  mongopool_app:insert(Pool, ?ACCESS_CODE_TABLE,
                       #{<<"_id">> => AccessCode, <<"token">> => AccessCode,
                         <<"grant">> => Context}),
  {ok, AppCtx}.

-spec associate_access_token(token(), grantctx(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
associate_access_token(AccessToken, Context, #{pool := Pool}=AppCtx) ->
  mongopool_app:insert(Pool, ?ACCESS_TOKEN_TABLE,
                       #{<<"_id">> => AccessToken, <<"token">> => AccessToken,
                         <<"grant">> => Context}),
  {ok, AppCtx}.

-spec resolve_refresh_token(token(), appctx()) ->
  {ok, {appctx(), grantctx()}} | {error, notfound}.
resolve_refresh_token(RefreshToken, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?REFRESH_TOKEN_TABLE,
                              #{<<"token">> => RefreshToken}) of
    #{<<"token">> := RefreshToken, <<"grant">> := Grant} ->
      {ok, {AppCtx, oauth2_mongopool_utils:dbMap2OAuth2List(Grant)}};
    #{} -> {error, notfound}
  end.

-spec resolve_access_code(token(), appctx()) ->
  {ok, {appctx(), grantctx()}} | {error, notfound}.
resolve_access_code(AccessCode, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?ACCESS_CODE_TABLE,
                              #{<<"token">> => AccessCode}) of
    #{<<"token">> := AccessCode, <<"grant">> := Grant} ->
      io:format("resolve_access_code: ~p~n",
                [oauth2_mongopool_utils:dbMap2OAuth2List(Grant)]),
      {ok, {AppCtx, oauth2_mongopool_utils:dbMap2OAuth2List(Grant)}};
    #{} -> {error, notfound}
  end.

-spec resolve_access_token(token(), appctx()) ->
  {ok, {appctx(), grantctx()}} | {error, notfound}.
resolve_access_token(AccessToken, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?ACCESS_TOKEN_TABLE,
                          #{<<"token">> => AccessToken}) of
    #{<<"token">> := AccessToken, <<"grant">> := Grant} ->
      {ok, {AppCtx, oauth2_mongopool_utils:dbMap2OAuth2List(Grant)}};
    #{} -> {error, notfound}
  end.

-spec revoke_refresh_token(token(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
revoke_refresh_token(RefreshToken, #{pool := Pool}=AppCtx) ->
  mongopool_app:delete(Pool, ?REFRESH_TOKEN_TABLE,
                       #{<<"token">> => RefreshToken}),
  {ok, AppCtx}.

-spec revoke_access_code(token(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
revoke_access_code(AccessCode, #{pool := Pool}=AppCtx) ->
  mongopool_app:delete(Pool, ?ACCESS_CODE_TABLE,
                       #{<<"token">> => AccessCode}),
  {ok, AppCtx}.

-spec revoke_access_token(token(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
revoke_access_token(AccessToken, #{pool := Pool}=AppCtx) ->
  mongopool_app:delete(Pool, ?ACCESS_TOKEN_TABLE,
                       #{<<"token">> => AccessToken}),
  {error, AppCtx}.

-spec get_client_identity(client(), appctx()) ->
  {ok, {appctx(), client()}} | {error, notfound | badsecret}.
get_client_identity({ClientId, ClientSecret}, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?CLIENT_TABLE, #{<<"_id">> => ClientId}) of
    #{<<"client_secret">> := ClientSecret}=Identity ->
      {ok, {AppCtx, Identity#{<<"client_secret">> => undefined}}};
    #{<<"client_secret">> := _WrongClientSecret} -> {error, badsecret};
    #{} -> {error, notfound}
  end.

-spec verify_redirection_uri(client(), binary(), appctx()) ->
  {ok, appctx()} | {error, notfound | baduri}.
verify_redirection_uri(#{redirect_uri := ClientUri}, ClientUri, AppCtx) ->
  {ok, {AppCtx, ClientUri}};
verify_redirection_uri(#{redirect_uri := <<>>}, _ClientUri, _AppCtx) ->
  {error, baduri};
verify_redirection_uri(#{redirect_uri := _WrongUri}, _ClientUri, _AppCtx) ->
  {error, baduri}.

-spec verify_client_scope(client(), scope(), appctx()) ->
  {ok, {appctx(), scope()}} | {error, notfound | badscope}.
verify_client_scope(#{<<"scope">> := RegisteredScope}, Scope, AppCtx) ->
  % FIXME errors check
  verify_scope(RegisteredScope, Scope, AppCtx).

-spec verify_resowner_scope(term(), scope(), appctx()) ->
  {ok, {appctx(), scope()}} | {error, notfound | badscope}.
verify_resowner_scope(#{<<"scope">> := RegisteredScope}, Scope, AppCtx) ->
  % FIXME errors check
  verify_scope(RegisteredScope, Scope, AppCtx).

-spec verify_scope(scope(), scope(), appctx()) ->
  {ok, {appctx(), scope()}} | {error, notfound | badscope}.
verify_scope(RegisteredScope, undefined, AppCtx) ->
  {ok, {AppCtx, RegisteredScope}};
verify_scope(_RegisteredScope, [], AppCtx) ->
  {ok, {AppCtx, []}};
verify_scope([], _Scope, _AppContext) ->
  {error, badscope};
verify_scope(RegisteredScope, Scope, AppCtx) ->
  io:format("verify_scope: ~p ~p~n", [RegisteredScope, Scope]),
  case oauth2_priv_set:is_subset(oauth2_priv_set:new(RegisteredScope),
                                 oauth2_priv_set:new(Scope)) of
    true -> {ok, {AppCtx, Scope}};
    false -> {error, badscope}
  end.

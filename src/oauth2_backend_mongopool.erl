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
-export([start/0,
         stop/0,
         add_client/4,
         add_resowner/3,
         add_resowner/4,
         add_resowner_scope/2,
         remove_resowner_scope/2,
         get_resowner_scope/1,
         get_client/1,
         get_resowner/1,
         delete_client/1,
         delete_resowner/1
         % authorize_access_token/2
        ]).

%%% OAuth2 backend functionality
-export([associate_access_code/3,
         associate_access_token/3,
         associate_refresh_token/3,
         authenticate_client/2,
         authenticate_user/2,
         get_client_identity/2,
         get_redirection_uri/2,
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
         is_authorized/2
        ]).

%%% Tables
-define(USER_TABLE, users).
-define(CLIENT_TABLE, clients).
-define(ACCESS_CODE_TABLE, access_codes).
-define(ACCESS_TOKEN_TABLE, access_tokens).
-define(REFRESH_TOKEN_TABLE, refresh_tokens).

% API implementation

stop() ->
  ok.

start() ->
  application:ensure_all_started(mongopool),
  {ok, initialized}.

%% @doc check object authorization
%%      if auth fail, then raise an exception not_authorized else return ok.
-spec is_authorized(oauth2:auth(), fun()) ->
  list() | no_return().
% TODO can be improved?
is_authorized(AccessToken, GetObjectScope)
  when is_function(GetObjectScope) ->
  % TODO add testsuite.
  case oauth2:verify_access_token(AccessToken, undefined) of
    {ok, {_AppContext, GrantCtx}} ->
      case lists:keyfind(<<"scope">>, 1, GrantCtx) of
        {<<"scope">>, PermittedScope} ->
          case esh_oauth2_backend:verify_scope(
                 PermittedScope, GetObjectScope(GrantCtx), undefined) of
            {ok, {_AppContext2, _VerifiedScope}} -> GrantCtx;
            {error, _ErrorType} -> throw(not_authorized)
          end;
        false -> throw(not_authorized)
      end;
    {error, _ErrorType} -> throw(not_authorized)
  end.

get_resowner_scope(Username) ->
  case mongopool_app:find_one(eshpool, ?USER_TABLE, #{<<"_id">> => Username}) of
    #{<<"scope">> := Scope} -> {ok, Scope};
    #{} -> throw(not_found)
  end.

% @doc add a new scope to user.
% @end
add_resowner_scope(Username, Scope) when is_binary(Scope) ->
  add_resowner_scope(Username, [Scope]);
add_resowner_scope(Username, Scope) when is_list(Scope) ->
  {ok, #{<<"scope">> := CurrentScope}} = get_resowner(Username),
  MergedScopes = lists:umerge(CurrentScope, Scope),
  mongopool_app:update(eshpool, ?USER_TABLE,
                   #{<<"_id">> => Username}, {<<"$set">>, MergedScopes}).

% @doc remove a scope from user.
% @end
remove_resowner_scope(Username, Scope) when is_binary(Scope) ->
  remove_resowner_scope(Username, [Scope]);
remove_resowner_scope(Username, Scope) when is_list(Scope) ->
  {ok, #{<<"scope">> := CurrentScope}} = get_resowner(Username),
  RemovedScopes = lists:subtract(CurrentScope, Scope),
  % FIXME update instead of insert
  mongopool_app:update(eshpool, ?USER_TABLE,
                   #{<<"_id">> => Username}, {<<"$set">>, RemovedScopes}).


-spec add_client(Id, Secret, RedirectUri, Scope) -> ok when
    Id          :: binary(),
    Secret      :: binary() | undefined,
    RedirectUri :: binary(),
    Scope       :: [binary()].
add_client(Id, Secret, RedirectUri, Scope) ->
  mongopool_app:insert(eshpool, ?CLIENT_TABLE, #{
                    <<"_id">> => Id,
                    % TODO remove client_id?
                    <<"client_id">> => Id,
                    <<"client_secret">> => Secret,
                    <<"redirect_uri">> => RedirectUri,
                    <<"scope">> => Scope
                   }).

-spec add_resowner(Username, Password, Email) ->
  {ok, {confirmator:token(), esh_worker_user_confirm:appctx()}} |
  {error, term()} when
    Username :: binary(),
    Password :: binary(),
    Email    :: binary().
add_resowner(Username, Password, Email) ->
  add_resowner(Username, Password, Email,
               [<< <<"users.">>/binary, Username/binary >>]),
  ok.

-spec add_resowner(Username, Password, Email, Scope) ->
  {ok, {confirmator:token(), esh_worker_user_confirm:appctx()}} |
  {error, term()} when
    Username  :: binary(),
    Password  :: binary(),
    Email     :: binary(),
    Scope     :: [binary()].
add_resowner(Username, Password, Email, Scope) ->
  {ok, {Cctx, _Pctx}} = esh_worker_user_confirm:init(),
  mongopool_app:insert(eshpool, ?USER_TABLE, #{
                  <<"_id">> => Username,
                  <<"username">> => Username,
                  <<"password">> => Password,
                  <<"email">> => Email,
                  <<"status">> => <<"register">>,
                  <<"_ctx">> => Cctx,
                  <<"scope">> => Scope}),
  esh_worker_user_confirm:register_user(Username, Username, Email,
                                        {Cctx, _Pctx}).

-spec delete_resowner(Username) -> ok when
    Username :: binary().
delete_resowner(Username) ->
  mongopool_app:delete(eshpool, ?USER_TABLE, #{<<"_id">> => Username}).

-spec delete_client(Id) -> ok when
    Id :: binary().
delete_client(Id) ->
  mongopool_app:delete(eshpool, ?CLIENT_TABLE, #{<<"_id">> => Id}).

get_resowner(Username) ->
  case mongopool_app:find_one(eshpool, ?USER_TABLE, #{<<"_id">> => Username}) of
    #{<<"_id">> := Username}=User -> {ok, User};
    #{} -> throw(user_not_found)
  end.

get_client(ClientId) ->
  case mongopool_app:find_one(eshpool, ?CLIENT_TABLE, #{<<"_id">> => ClientId}) of
    #{<<"_id">> := ClientId}=Client -> {ok, Client};
    % TODO return throw(client_not_found)? (see also authenticate_client)
    #{} -> {error, not_found}
  end.

%%% Oauth2 Backend API implementation

authenticate_user({Username, Password}, AppCtx) ->
  try
    case get_resowner(Username) of
      {ok, #{<<"password">> := Password} = Identity} ->
        {ok, {AppCtx, Identity#{<<"password">> := undefined}}};
      {ok, #{<<"password">> := _WrongPassword}} ->
        {error, "Wrong password"}
    end
  catch
    user_not_found -> {error, not_found}
  end.

authenticate_client({ClientId, ClientSecret}, AppCtx) ->
  case get_client(ClientId) of
    {ok, #{<<"client_secret">> := ClientSecret}=Identity} ->
      {ok, {AppCtx, Identity#{<<"client_secret">> := undefined}}};
    {ok, #{<<"client_secret">> := _WrongClientSecret}} ->
      {error, "Wrong client secret"};
    {error, ErrorType} ->
      {error, ErrorType}
  end.

associate_refresh_token(RefreshToken, Context, AppCtx) ->
  mongopool_app:insert(eshpool, ?REFRESH_TOKEN_TABLE,
                   #{<<"_id">> => RefreshToken, <<"token">> => RefreshToken,
                     <<"grant">> => Context}),
  {ok, AppCtx}.

associate_access_code(AccessCode, Context, AppCtx) ->
  mongopool_app:insert(eshpool, ?ACCESS_CODE_TABLE,
                   #{<<"_id">> => AccessCode, <<"token">> => AccessCode,
                     <<"grant">> => Context}),
  {ok, AppCtx}.

associate_access_token(AccessToken, Context, AppCtx) ->
  mongopool_app:insert(eshpool, ?ACCESS_TOKEN_TABLE,
                   #{<<"_id">> => AccessToken, <<"token">> => AccessToken,
                     <<"grant">> => Context}),
  {ok, AppCtx}.

resolve_refresh_token(RefreshToken, AppCtx) ->
  case mongopool_app:find_one(eshpool, ?REFRESH_TOKEN_TABLE,
                          #{<<"token">> => RefreshToken}) of
    #{<<"token">> := RefreshToken, <<"grant">> := Grant} ->
      {ok, {AppCtx, eshc_utils:dbMap2OAuth2List(Grant)}};
    #{} -> {error, not_found}
  end.

resolve_access_code(AccessCode, AppCtx) ->
  case mongopool_app:find_one(eshpool, ?ACCESS_CODE_TABLE,
                          #{<<"token">> => AccessCode}) of
    #{<<"token">> := AccessCode, <<"grant">> := Grant} ->
      io:format("resolve_access_code: ~p~n",
                [eshc_utils:dbMap2OAuth2List(Grant)]),
      {ok, {AppCtx, eshc_utils:dbMap2OAuth2List(Grant)}};
    #{} -> {error, not_found}
  end.

resolve_access_token(AccessToken, AppCtx) ->
  case mongopool_app:find_one(eshpool, ?ACCESS_TOKEN_TABLE,
                          #{<<"token">> => AccessToken}) of
    #{<<"token">> := AccessToken, <<"grant">> := Grant} ->
      {ok, {AppCtx, eshc_utils:dbMap2OAuth2List(Grant)}};
    #{} -> {error, not_found}
  end.

revoke_refresh_token(RefreshToken, AppCtx) ->
  mongopool_app:delete(eshpool, ?REFRESH_TOKEN_TABLE,
                   #{<<"token">> => RefreshToken}),
  {ok, AppCtx}.

revoke_access_code(AccessCode, AppCtx) ->
  mongopool_app:delete(eshpool, ?ACCESS_CODE_TABLE,
                   #{<<"token">> => AccessCode}),
  {ok, AppCtx}.

revoke_access_token(AccessToken, AppCtx) ->
  mongopool_app:delete(eshpool, ?ACCESS_TOKEN_TABLE,
                   #{<<"token">> => AccessToken}),
  {error, AppCtx}.

get_redirection_uri(ClientId, AppCtx) ->
  case get_client(ClientId) of
    {ok, #{<<"redirect_uri">> := RedirectUri}} ->
      {ok, {AppCtx, RedirectUri}};
    {error, ErrorType} -> {error, ErrorType}
  end.

get_client_identity(ClientId, AppCtx) ->
  case get_client(ClientId) of
    {ok, #{<<"client_id">> := ClientId}=Identity} ->
      {ok, {AppCtx, Identity#{<<"client_secret">> => undefined}}};
    {error, ErrorType} -> {error, ErrorType}
  end.

verify_redirection_uri(Client, ClientUri, AppCtx) ->
  RedirectUri = maps:get(<<"redirect_uri">>, Client),
  case ClientUri of
    RedirectUri -> {ok, {AppCtx, RedirectUri}};
    _Error -> {error, mismatch}
  end.

verify_client_scope(#{<<"scope">> := RegisteredScope}, Scope, AppCtx) ->
  verify_scope(RegisteredScope, Scope, AppCtx).

verify_resowner_scope(#{<<"scope">> := RegisteredScope}, Scope, AppCtx) ->
  verify_scope(RegisteredScope, Scope, AppCtx).

verify_scope(RegisteredScope, undefined, AppCtx) ->
  {ok, {AppCtx, RegisteredScope}};
verify_scope(_RegisteredScope, [], AppCtx) ->
  {ok, {AppCtx, []}};
verify_scope([], _Scope, _AppContext) ->
  {error, invalid_scope};
verify_scope(RegisteredScope, Scope, AppCtx) ->
  io:format("verify_scope: ~p ~p~n", [RegisteredScope, Scope]),
  case oauth2_priv_set:is_subset(oauth2_priv_set:new(RegisteredScope),
                                 oauth2_priv_set:new(Scope)) of
    true ->
      {ok, {AppCtx, Scope}};
    false ->
      {error, badscope}
  end.

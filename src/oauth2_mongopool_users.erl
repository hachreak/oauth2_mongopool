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
%%% @doc implement function to manage users.
%%% @end

-module(oauth2_mongopool_users).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-export([
         add_resowner/4,
         add_resowner/5,
         add_resowner_scope/3,
         delete_resowner/2,
         get_resowner/2,
         get_resowner_scope/2,
         remove_resowner_scope/3
        ]).

% FIXME use the application environment
-define(USER_TABLE, users).

%%%_ * Types -----------------------------------------------------------

-type user()     :: oauth2:user().
-type appctx()   :: oauth2:appctx().
-type scope()    :: oauth2:scope().

% API implementation

-spec add_resowner(binary(), binary(), binary(), appctx()) ->
  {ok, appctx()} | {error, term()}.
add_resowner(UserId, Password, Email, AppCtx) ->
  add_resowner(UserId, Password, Email,
               [<< <<"users.">>/binary, UserId/binary >>], AppCtx).

-spec add_resowner(binary(), binary(), binary(), scope(), appctx()) ->
  {ok, appctx()} | {error, term()}.
add_resowner(UserId, Password, Email, Scope, #{pool := Pool}=AppCtx) ->
  % {ok, {Cctx, _Pctx}} = esh_worker_user_confirm:init(),
  mongopool_app:insert(Pool, ?USER_TABLE, #{
                  <<"_id">> => UserId,
                  <<"username">> => UserId,
                  <<"password">> => Password,
                  <<"email">> => Email,
                  <<"status">> => <<"register">>,
                  % <<"_ctx">> => Cctx,
                  <<"scope">> => Scope}),
  % FIXME
  % esh_worker_user_confirm:register_user(UserId, UserId, Email,
                                        % {Cctx, _Pctx}),
  {ok, AppCtx}.

% @doc add a new scope to user.
-spec add_resowner_scope(binary(), scope(), appctx()) -> ok.
add_resowner_scope(UserId, Scope, AppCtx) when is_binary(Scope) ->
  add_resowner_scope(UserId, [Scope], AppCtx);
add_resowner_scope(UserId, Scope, #{pool := Pool}=AppCtx)
  when is_list(Scope) ->
  {ok, #{<<"scope">> := CurrentScope}} = get_resowner(UserId, AppCtx),
  MergedScopes = lists:umerge(CurrentScope, Scope),
  mongopool_app:update(Pool, ?USER_TABLE,
                       #{<<"_id">> => UserId}, {<<"$set">>, MergedScopes}).

-spec delete_resowner(binary(), appctx()) -> {ok, appctx()} | {error, term()}.
delete_resowner(UserId, #{pool := Pool}=AppCtx) ->
  mongopool_app:delete(Pool, ?USER_TABLE, #{<<"_id">> => UserId}),
  {ok, AppCtx}.

-spec get_resowner(binary(), appctx()) ->
  {ok, {appctx(), user()}} | no_return().
get_resowner(UserId, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?USER_TABLE, #{<<"_id">> => UserId}) of
    #{<<"_id">> := UserId}=User -> {ok, {AppCtx, User}};
    #{} -> throw(notfound)
  end.

-spec get_resowner_scope(binary(), appctx()) ->
  {ok, {appctx(), scope()}} | no_return().
get_resowner_scope(UserId, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?USER_TABLE, #{<<"_id">> => UserId}) of
    #{<<"scope">> := Scope} -> {ok, {AppCtx, Scope}};
    #{} -> throw(not_found)
  end.

% @doc remove a scope from user.
-spec remove_resowner_scope(binary(), scope(), appctx()) -> ok.
remove_resowner_scope(UserId, Scope, AppCtx) when is_binary(Scope) ->
  remove_resowner_scope(UserId, [Scope], AppCtx);
remove_resowner_scope(UserId, Scope, #{pool := Pool}=AppCtx)
  when is_list(Scope) ->
  {ok, #{<<"scope">> := CurrentScope}} = get_resowner(UserId, AppCtx),
  RemovedScopes = lists:subtract(CurrentScope, Scope),
  mongopool_app:update(Pool, ?USER_TABLE,
                       #{<<"_id">> => UserId}, {<<"$set">>, RemovedScopes}).

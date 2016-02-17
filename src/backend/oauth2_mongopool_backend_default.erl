%%% @author Leonardo Rossi <leonardo.rossi@studenti.unipr.it>
%%% @copyright (C) 2016 Leonardo Rossi
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
%%% @doc Default backend for clients and users
%%% @end

-module(oauth2_mongopool_backend_default).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-behaviour(oauth2_mongopool_backend).

% behaviour API
-export([get_user/2, get_client_identity/2, get_client/2]).

% API
-export([create_user/2, create_client/2]).

-type appctx()   :: oauth2:appctx().
-type user()     :: oauth2:user().
-type client()   :: oauth2:client().
-type clientid() :: binary().

-define(USERS_TABLE, users).
-define(CLIENTS_TABLE, clients).

%%% Backend API

-spec get_user(user(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound | badpass}.
get_user({UserId, Password}, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(
        Pool, ?USERS_TABLE, #{<<"_id">> => UserId}) of
    #{<<"_id">> := UserId, <<"password">> := Password}=Identity ->
      {ok, {AppCtx, Identity#{<<"password">> => undefined}}};
    #{<<"_id">> := UserId, <<"password">> := _WrongPassword} ->
      {error, badpass};
    _Rest -> {error, notfound}
  end.

-spec get_client_identity(clientid(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound}.
get_client_identity(ClientId, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(
        Pool, ?CLIENTS_TABLE, #{<<"_id">> => ClientId}) of
    #{<<"_id">> := ClientId}=Identity ->
      {ok, {AppCtx, Identity#{<<"client_secret">> => undefined}}};
    _Rest -> {error, notfound}
  end.

-spec get_client(client(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound | badpass}.
get_client({ClientId, ClientSecret}, AppCtx) ->
  case get_client_identity(ClientId, AppCtx) of
    {ok, {_, #{<<"client_secret">> := ClientSecret}}}=Result -> Result;
    {ok, {_, #{<<"client_secret">> := _WrongClientSecret}}} ->
      {error, badpass};
    Rest -> Rest
  end.

%%% API

-spec create_user(user(), appctx()) -> {ok, appctx()} | {error, term()}.
create_user({UserId, Password}, #{pool := Pool}=AppCtx) ->
  User = #{
    <<"_id">> => UserId,
    <<"password">> => Password
  },
  mongopool_app:insert(Pool, ?USERS_TABLE, User),
  {ok, AppCtx}.

-spec create_client(client(), appctx()) -> {ok, appctx()} | {error, term()}.
create_client({ClientId, ClientSecret}, #{pool := Pool}=AppCtx) ->
  Client = #{
    <<"_id">> => ClientId,
    <<"client_secret">> => ClientSecret
  },
  mongopool_app:insert(Pool, ?CLIENTS_TABLE, Client),
  {ok, AppCtx}.

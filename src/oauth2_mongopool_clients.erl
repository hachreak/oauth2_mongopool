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

-module(oauth2_mongopool_clients).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-export([
         add_client/5,
         delete_client/2,
         get_client/2
        ]).

% FIXME use the application environment
-define(CLIENT_TABLE, clients).

%%%_ * Types -----------------------------------------------------------

-type client()   :: oauth2:client().
-type appctx()   :: oauth2:appctx().
-type scope()    :: oauth2:scope().

% API implementation

-spec add_client(binary(), binary(), binary(), scope(), appctx()) ->
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

-spec delete_client(binary(), appctx()) -> {ok, appctx()} | {error, term()}.
delete_client(ClientId, #{pool := Pool}=AppCtx) ->
  mongopool_app:delete(Pool, ?CLIENT_TABLE, #{<<"_id">> => ClientId}),
  {ok, AppCtx}.

-spec get_client(binary(), appctx()) ->
  {ok, {appctx(), client()}} | {error, notfound}.
get_client(ClientId, #{pool := Pool}=AppCtx) ->
  case mongopool_app:find_one(Pool, ?CLIENT_TABLE, #{<<"_id">> => ClientId}) of
    #{<<"_id">> := ClientId}=Client -> {ok, {AppCtx, Client}};
    _Rest -> {error, notfound}
  end.

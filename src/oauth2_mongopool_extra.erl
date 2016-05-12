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
%%% @doc Extra functions..
%%% @end

-module(oauth2_mongopool_extra).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-export([authorize_code_retrieval/2]).

%%% Tables
-define(ACCESS_CODE_TABLE, access_codes).

%%% Macros ===========================================================
-define(BACKEND, (oauth2_mongopool_config:backend())).

%%%_ * Types -----------------------------------------------------------

-type appctx()   :: oauth2_mongopool:appctx().
-type client()   :: oauth2:client().
-type clientid() :: oauth2_mongopool_backend:clientid().
-type token()    :: oauth2:token().

%%%_ * Functions -------------------------------------------------------


-spec authorize_code_retrieval(client(), appctx()) ->
    {ok, {appctx(), list(token())}} | {error, not_authorized}.
authorize_code_retrieval({ClientId, ClientSecret},
                         #{backendctx := BackendCtx}=AppCtx) ->
  case ?BACKEND:authenticate_client(ClientId, ClientSecret, BackendCtx) of
    {error, _ErrorType} -> {error, not_authorized};
    {ok, {_BackendCtx, Client}} ->
      {ok, {AppCtx, resolve_all_access_code(
                      maps:get(<<"_id">>, Client), AppCtx)}}
  end.


%% Private functions

-spec resolve_all_access_code(clientid(), appctx()) -> list(token()).
resolve_all_access_code(ClientId, #{pool := Pool}) ->
  Cursor = mongopool_app:find(Pool, ?ACCESS_CODE_TABLE,
                              #{<<"grant.client._id">> => ClientId}),
  [Token || #{<<"token">> := Token} <- mc_cursor:rest(Cursor)].

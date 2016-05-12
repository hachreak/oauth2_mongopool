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

-export([resolve_auth_codes/2, resolve_access_tokens/2]).

%%% Tables
-define(ACCESS_CODE_TABLE, access_codes).
-define(ACCESS_TOKEN_TABLE, access_tokens).

%%% Macros ===========================================================
-define(BACKEND, (oauth2_mongopool_config:backend())).

%%%_ * Types -----------------------------------------------------------

-type appctx()   :: oauth2_mongopool:appctx().
-type clientid() :: oauth2_mongopool_backend:clientid().
-type token()    :: oauth2:token().

%%%_ * Functions -------------------------------------------------------

-spec resolve_auth_codes(clientid(), appctx()) -> list(token()).
resolve_auth_codes(ClientId, AppCtx) ->
  resolve_all_codes(ClientId, ?ACCESS_CODE_TABLE, AppCtx).

-spec resolve_access_tokens(clientid(), appctx()) -> list(token()).
resolve_access_tokens(ClientId, AppCtx) ->
  resolve_all_codes(ClientId, ?ACCESS_TOKEN_TABLE, AppCtx).


%% Private functions

-spec resolve_all_codes(clientid(), atom(), appctx()) -> list(token()).
resolve_all_codes(ClientId, Table, #{pool := Pool}) ->
  Cursor = mongopool_app:find(Pool, Table,
                              #{<<"grant.client._id">> => ClientId}),
  [Token || #{<<"token">> := Token} <- mc_cursor:rest(Cursor)].

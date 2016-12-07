%%% @author Leonardo Rossi <leonardo.rossi@studenti.unipr.it>
%%% @copyright (C) 2015, 2016 Leonardo Rossi
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
%%% @doc Utilities.
%%% @end

-module(oauth2_mongopool_utils).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-export([get_scope/1, get_cid/1, get_userid/1,
         copy_if_exists/4, get_token_refresh/1
        ]).

-type grantctx() :: oauth2:context().
-type scope()    :: oauth2:scope().
-type token()    :: oauth2:token().

% @doc get scope from a grantctx
% @end
-spec get_scope(grantctx()) -> scope().
get_scope(GrantCtx) ->
  proplists:get_value(<<"scope">>, GrantCtx).

% @doc get refresh token from a grantctx
% @end
-spec get_token_refresh(grantctx()) -> token() | undefined.
get_token_refresh(GrantCtx) ->
  proplists:get_value(<<"refresh_token">>, GrantCtx).

% @doc get client id from a grantctx
% @end
-spec get_cid(grantctx()) -> scope().
get_cid(GrantCtx) ->
  get_id(proplists:get_value(<<"client">>, GrantCtx)).

% @doc get user id from a grantctx
% @end
-spec get_userid(grantctx()) -> scope().
get_userid(GrantCtx) ->
  get_id(proplists:get_value(<<"resource_owner">>, GrantCtx)).

copy_if_exists(KeyOrig, KeyDest, Orig, Dest) ->
  try
    #{KeyOrig := Value} = Orig,
    Dest#{KeyDest => Value}
  catch
    error:{badmatch, _} -> Dest
  end.

%% private functions

-spec get_id(undefined | map()) -> binary().
get_id(undefined) -> undefined;
get_id(#{<<"_id">> := Id}) -> Id.

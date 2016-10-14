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

-export([
         resolve_auth_codes/2,
         resolve_access_tokens/2,
         resolve_refresh_tokens/2,
         exists_auth_code/3,
         resolve_user_auth_codes/2,
         revoke_access_codes/2
        ]).

%%% Tables
-define(ACCESS_CODE_TABLE, access_codes).
-define(ACCESS_TOKEN_TABLE, access_tokens).
-define(REFRESH_TOKEN_TABLE, refresh_tokens).

%%% Macros ===========================================================
-define(BACKEND, (oauth2_mongopool_config:backend())).

%%%_ * Types -----------------------------------------------------------

-type appctx()   :: oauth2_mongopool:appctx().
-type clientid() :: term().
-type token()    :: oauth2:token().

%%%_ * Functions -------------------------------------------------------

-spec revoke_access_codes(binary(), appctx()) -> {ok, appctx}.
revoke_access_codes(UserId, #{pool := Pool}=AppCtx) ->
  mongopool_app:delete(Pool, ?ACCESS_CODE_TABLE,
                       #{<<"grant.resource_owner._id">> => UserId}),
  {ok, AppCtx}.

-spec resolve_user_auth_codes(binary(), appctx()) -> list(token()).
resolve_user_auth_codes(UserId, AppCtx) ->
  TokensAuthNotConverted = resolve(
    [{<<"grant.resource_owner._id">>, UserId}], ?ACCESS_CODE_TABLE, AppCtx),
  TokensAuthConverted = resolve(
    [{<<"grant.resource_owner._id">>, UserId},
     {<<"grant.code">>, {'$exists', true}}],
    ?ACCESS_TOKEN_TABLE, AppCtx),
  lists:merge(
    extract_user_tokens_auth(<<"token">>, TokensAuthNotConverted),
    extract_user_tokens_auth(<<"grant.code">>, TokensAuthConverted)).

-spec exists_auth_code(binary(), token(), appctx()) -> boolean().
exists_auth_code(UserId, TokenAuth, AppCtx) ->
  % TODO improve query
  resolve(
    [{<<"grant.resource_owner._id">>, UserId},{<<"token">>, TokenAuth}],
    ?ACCESS_TOKEN_TABLE, AppCtx) =/= [].

-spec resolve_auth_codes(clientid(), appctx()) -> list(token()).
resolve_auth_codes(ClientId, AppCtx) ->
  extract_auth_codes(resolve_all_codes(ClientId, ?ACCESS_CODE_TABLE, AppCtx)).

-spec resolve_access_tokens(
        {cid, clientid()} | {auth, token()}, appctx()) -> list(token()).
resolve_access_tokens({cid, ClientId}, AppCtx) ->
  extract_access_tokens(
    resolve_all_codes(ClientId, ?ACCESS_TOKEN_TABLE, AppCtx));
resolve_access_tokens({token_auth, TokenAuth}, AppCtx) ->
  extract_access_tokens(
    resolve([{<<"grant.code">>, TokenAuth}], ?ACCESS_TOKEN_TABLE, AppCtx)).

-spec resolve_refresh_tokens(clientid(), appctx()) -> list(token()).
resolve_refresh_tokens(ClientId, AppCtx) ->
  extract_refresh_tokens(
    resolve_all_codes(ClientId, ?REFRESH_TOKEN_TABLE, AppCtx)).

%% Private functions

-spec resolve(list({binary(), term()}), atom(), appctx()) -> list(token()).
resolve(RequiredFilters, Table, #{pool := Pool}) ->
  ExpiryFilters = [{<<"grant.expiry_time">>, {'$gt', get_now()}}],
  Filters = lists:merge(RequiredFilters, ExpiryFilters),
  Cursor = mongopool_app:find(Pool, Table, {'$query', {'$and', Filters}}),
  Tokens = mc_cursor:rest(Cursor),
  mc_cursor:close(Cursor),
  [Token#{
     <<"grant">> => maps:from_list(
                      oauth2_mongopool_utils:dbMap2OAuth2List(GrantCtx))}
      || #{<<"grant">> := GrantCtx}=Token <- Tokens].

-spec resolve_all_codes(clientid(), atom(), appctx()) -> list(token()).
resolve_all_codes(ClientId, Table, AppCtx) ->
  resolve([{<<"grant.client._id">>, ClientId}], Table, AppCtx).

-spec get_now() -> non_neg_integer().
get_now() ->
    {Mega, Secs, _} = os:timestamp(),
    Mega * 1000000 + Secs.

-spec extract_access_tokens(list()) -> list().
extract_access_tokens(Rows) ->
  lists:map(fun(Row) ->
      #{<<"grant">> := GrantCtx, <<"token">> := Token} = Row,
      #{<<"expiry_time">> := ExpiryTime, <<"scope">> := Scope} = GrantCtx,
      oauth2_mongopool_utils:copy_if_exists(
        <<"refresh_token">>, <<"token_refresh">>, GrantCtx,
        #{<<"expiry_time">> => ExpiryTime,
          <<"scope">> => Scope,
          <<"token_access">> => Token
      })
    end, Rows).

-spec extract_refresh_tokens(list()) -> list().
extract_refresh_tokens(Tokens) ->
  [#{
     <<"expiry_time">> => ExpiryTime,
     <<"scope">> => Scope,
     <<"token_refresh">> => Token
    } || #{
      <<"grant">> := #{
        <<"expiry_time">> := ExpiryTime,
        <<"scope">> := Scope
      },
      <<"token">> := Token
    } <- Tokens].

-spec extract_user_tokens_auth(binary(), list()) -> list().
extract_user_tokens_auth(<<"token">>, Tokens) ->
  [#{
     <<"clientid">> => ClientId,
     <<"expiry_time">> => ExpiryTime,
     <<"scope">> => Scope,
     <<"converted">> => <<"false">>,
     <<"token_auth">> => Token
    } || #{
      <<"grant">> := #{
        <<"expiry_time">> := ExpiryTime,
        <<"scope">> := Scope,
        <<"client">> := #{
          <<"_id">> := ClientId
        }
      },
      <<"token">> := Token
    } <- Tokens];
extract_user_tokens_auth(<<"grant.code">>, Tokens) ->
  [#{
     <<"clientid">> => ClientId,
     <<"expiry_time">> => ExpiryTime,
     <<"scope">> => Scope,
     <<"converted">> => <<"true">>,
     <<"token_auth">> => Token
    } || #{
      <<"grant">> := #{
        <<"code">> := Token,
        <<"expiry_time">> := ExpiryTime,
        <<"scope">> := Scope,
        <<"client">> := #{
          <<"_id">> := ClientId
        }
      }
    } <- Tokens].

-spec extract_auth_codes(list()) -> list().
extract_auth_codes(Tokens) ->
  [#{
     <<"expiry_time">> => ExpiryTime,
     <<"scope">> => Scope,
     <<"token_auth">> => Token
    } || #{
      <<"grant">> := #{
        <<"expiry_time">> := ExpiryTime,
        <<"scope">> := Scope
      },
      <<"token">> := Token
    } <- Tokens].

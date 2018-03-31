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
         revoke_user_access_codes/2,
         revoke_access_code/2,
         revoke_access_token/2
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
-type filters()  :: list({binary(), term()}).
-type fqscopes() :: oauth2_scope_strategy_fq:fqscopes().
-type token()    :: oauth2:token().

%%%_ * Functions -------------------------------------------------------

-spec revoke_access_token(token(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
revoke_access_token(AccessToken, AppCtx) ->
  oauth2_backend_mongopool:revoke_access_token(AccessToken, AppCtx).

-spec revoke_access_code(token(), appctx()) ->
  {ok, appctx()} | {error, notfound}.
revoke_access_code(AccessCode, AppCtx) ->
  oauth2_backend_mongopool:revoke_access_code(AccessCode, AppCtx).

-spec revoke_user_access_codes(
    {not_converted | converted | all, binary()}, appctx()) -> {ok, appctx}.
revoke_user_access_codes({not_converted, UserId}, #{pool := Pool}=AppCtx) ->
  mongopool_app:delete(Pool, ?ACCESS_CODE_TABLE,
                       #{<<"grant.resource_owner._id">> => UserId}),
  {ok, AppCtx};
revoke_user_access_codes({converted, UserId}, #{pool := Pool}=AppCtx) ->
  mongopool_app:delete(Pool, ?ACCESS_TOKEN_TABLE,
                       #{<<"grant.resource_owner._id">> => UserId,
                         <<"grant.client">> => {'$ne', undefined}}),
  {ok, AppCtx};
revoke_user_access_codes({all, UserId}, AppCtx) ->
  revoke_user_access_codes({not_converted, UserId}, AppCtx),
  revoke_user_access_codes({converted, UserId}, AppCtx),
  {ok, AppCtx}.

-spec resolve_user_auth_codes(
    {not_converted | converted | all, binary()}, appctx()) -> list(token()).
resolve_user_auth_codes({not_converted, UserId}, AppCtx) ->
  extract_user_tokens_auth(
    <<"_id">>, resolve_user_tokens(UserId, [], ?ACCESS_CODE_TABLE, AppCtx));
resolve_user_auth_codes({converted, UserId}, AppCtx) ->
  extract_user_tokens_auth(
    <<"grant.code">>,
    resolve_user_tokens(
      UserId, [{<<"grant.code">>, {'$ne', undefined}}],
      ?ACCESS_TOKEN_TABLE, AppCtx));
resolve_user_auth_codes({all, UserId}, AppCtx) ->
  lists:merge(
    resolve_user_auth_codes({not_converted, UserId}, AppCtx),
    resolve_user_auth_codes({converted, UserId}, AppCtx)).

-spec exists_auth_code(binary(), token(), appctx()) -> boolean().
exists_auth_code(UserId, TokenAuth, AppCtx) ->
  % TODO improve query
  resolve_user_tokens(
    UserId, [{<<"_id">>, TokenAuth}], ?ACCESS_CODE_TABLE, AppCtx) =/= [].

-spec resolve_auth_codes(clientid(), appctx()) -> list(token()).
resolve_auth_codes(Cid, AppCtx) ->
  extract_auth_codes(resolve_all_codes(Cid, ?ACCESS_CODE_TABLE, AppCtx)).

-spec resolve_access_tokens(
        %{cid, clientid(), fqscopes()} |
        {cid, clientid()} |
        {auth, binary(), token()}, appctx()) ->
    list(token()).
% resolve_access_tokens({cid, Cid, FQScopes}, AppCtx) ->
%   Scopes = oauth2_scope_strategy_fq:implode(FQScopes),
%   Filters = lists:map(fun(SingleScope) ->
%       RegEx = << <<"^">>/binary, SingleScope/binary, <<"$">>/binary >>,
%       {<<"grant.scope">>, {'$regex', RegEx}}
%     end, Scopes),
%   Query = [{<<"grant.client._id">>, Cid}, {'$or', Filters}],
%   extract_access_tokens(resolve(Query, ?ACCESS_TOKEN_TABLE, AppCtx));
resolve_access_tokens({owner, UserId, Limit}, AppCtx) ->
  % get token where he is the resource owner or the resource beneficiary
  Query = [{'$or', [
            {<<"grant.resource_benefit._id">>, UserId},
            {'$and', [{<<"grant.resource_benefit._id">>, undefined},
                      {<<"grant.resource_owner._id">>, UserId}]}
          ]}],
  extract_access_tokens(resolve(Query, Limit, ?ACCESS_TOKEN_TABLE, AppCtx));
resolve_access_tokens({cid, Cid}, AppCtx) ->
  extract_access_tokens(
    resolve_all_codes(Cid, ?ACCESS_TOKEN_TABLE, AppCtx));
resolve_access_tokens({token_auth, UserId, TokenAuth}, AppCtx) ->
  extract_access_tokens(
    resolve_user_tokens(
      UserId, [{<<"grant.code">>, TokenAuth}], ?ACCESS_TOKEN_TABLE, AppCtx)).

-spec resolve_refresh_tokens(clientid(), appctx()) -> list(token()).
resolve_refresh_tokens(Cid, AppCtx) ->
  extract_refresh_tokens(
    resolve_all_codes(Cid, ?REFRESH_TOKEN_TABLE, AppCtx)).

%% Private functions

-spec resolve_user_tokens(binary(), filters(), atom(), appctx()) ->
    list(token()).
resolve_user_tokens(UserId, RequiredFilters, Table, AppCtx) ->
  UserFilters = [{<<"grant.resource_owner._id">>, UserId}],
  Filters = lists:merge(RequiredFilters, UserFilters),
  resolve(Filters, Table, AppCtx).

-spec resolve_all_codes(clientid(), atom(), appctx()) -> list(token()).
resolve_all_codes(Cid, Table, AppCtx) ->
  resolve([{<<"grant.client._id">>, Cid}], Table, AppCtx).

resolve(RequiredFilters, Table, AppCtx) ->
  resolve(RequiredFilters, infinity, Table, AppCtx).

-spec resolve(filters(), integer()|infinity, atom(), appctx()) -> list(token()).
resolve(RequiredFilters, 0, Table, AppCtx) ->
  resolve(RequiredFilters, infinity, Table, AppCtx);
resolve(RequiredFilters, Limit, Table, #{pool := Pool}) ->
  ExpiryFilters = [{<<"grant.expiry_time">>, {'$gt', get_now()}}],
  Filters = lists:merge(RequiredFilters, ExpiryFilters),
  Cursor = mongopool_app:find(Pool, Table, {'$query', {'$and', Filters}}),
  Tokens = mc_cursor:take(Cursor, Limit),
  mc_cursor:close(Cursor),
  Tokens.

-spec get_now() -> non_neg_integer().
get_now() ->
    {Mega, Secs, _} = os:timestamp(),
    Mega * 1000000 + Secs.

-spec extract_access_tokens(list()) -> list().
extract_access_tokens(Rows) ->
  lists:map(fun(Row) ->
      #{<<"grant">> := GrantCtx, <<"_id">> := Token} = Row,
      #{<<"expiry_time">> := ExpiryTime, <<"scope">> := Scope} = GrantCtx,
      User = case maps:get(<<"resource_benefit">>, GrantCtx, undefined) of
        undefined -> maps:get(<<"resource_owner">>, GrantCtx);
        RB -> RB
      end,
      #{<<"_id">> := UserId} = User,
      oauth2_mongopool_utils:copy_if_exists(
        <<"refresh_token">>, <<"token_refresh">>, GrantCtx,
        #{<<"expiry_time">> => ExpiryTime,
          <<"scope">> => Scope,
          <<"token_access">> => Token,
          <<"userid">> => UserId
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
      <<"_id">> := Token
    } <- Tokens].

-spec extract_user_tokens_auth(binary(), list()) -> list().
extract_user_tokens_auth(<<"_id">>, Tokens) ->
  [#{
     <<"clientid">> => Cid,
     <<"expiry_time">> => ExpiryTime,
     <<"scope">> => Scope,
     <<"converted">> => <<"false">>,
     <<"token_auth">> => Token
    } || #{
      <<"grant">> := #{
        <<"expiry_time">> := ExpiryTime,
        <<"scope">> := Scope,
        <<"client">> := #{
          <<"_id">> := Cid
        }
      },
      <<"_id">> := Token
    } <- Tokens];
extract_user_tokens_auth(<<"grant.code">>, Tokens) ->
  lists:map(
    fun(#{
      <<"grant">> := #{
        <<"code">> := Token,
        <<"expiry_time">> := ExpiryTime,
        <<"scope">> := Scope
      }=Grant
    }) ->
      ResOwner = get(<<"resource_owner">>, Grant, #{}),
      ResBenefit = get(<<"resource_benefit">>, Grant, #{}),
      Client = get(<<"client">>, Grant, #{}),
      #{
        <<"userid">> => get(<<"_id">>, ResOwner, undefined),
        <<"benificiary">> => get(<<"_id">>, ResBenefit, undefined),
        <<"clientid">> => get(<<"_id">>, Client, undefined),
        <<"expiry_time">> => ExpiryTime,
        <<"scope">> => Scope,
        <<"converted">> => <<"true">>,
        <<"token_auth">> => Token
      }
    end, Tokens).

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
      <<"_id">> := Token
    } <- Tokens].

get(_, undefined, _) -> undefined;
get(Key, Map, Default) ->maps:get(Key, Map, Default).

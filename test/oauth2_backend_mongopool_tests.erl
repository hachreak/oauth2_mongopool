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
%%% @doc Oauth2 mongopool backend - Tests.
%%% @end

-module(oauth2_backend_mongopool_tests).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-include_lib("eunit/include/eunit.hrl").

oauth2_backend_mongopool_test_() ->
  {setup,
    fun start/0,
    fun stop/1,
    fun (SetupData) ->
        [
         verify_scope_test(SetupData),
         associate_refresh_token_test(SetupData),
         associate_access_token_test(SetupData),
         associate_access_code_test(SetupData),
         authenticate_user_test(SetupData),
         authenticate_client_test(SetupData),
         get_client_identity_test(SetupData),
         verify_redirection_uri_test(SetupData),
         verify_client_scope_test(SetupData),
         verify_resowner_scope_test(SetupData)
        ]
    end
  }.

start() ->
  meck:new(mongopool_app, [no_link, passthrough, no_history, non_strict]),
  application:set_env(oauth2, backend, oauth2_backend_mongopool).

find_one(Fun) when is_function(Fun) ->
  meck:expect(mongopool_app, find_one, 3, Fun);
find_one(Return) ->
  meck:expect(mongopool_app, find_one, 3, fun(_A, _B, _C) -> Return end).

insert(Fun) when is_function(Fun) ->
  meck:expect(mongopool_app, insert, 3, Fun).

delete(Fun) when is_function(Fun) ->
  meck:expect(mongopool_app, delete, 3, Fun);
delete(Return) ->
  meck:expect(mongopool_app, delete, 3, fun(_A, _B, _C) -> Return end).

stop(_Pid) ->
  meck:validate(mongopool_app),
  meck:unload(mongopool_app).

verify_scope_test(_) ->
  fun() ->
      ?assertEqual({ok,{undefined,[<<"all.users.testuser.boxes">>]}},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"users.testuser.boxes">>],
                     [<<"users.testuser.boxes">>],
                     undefined
                    )),
      ?assertEqual({error, badscope},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"users.testuser.boxes">>],
                     undefined,
                     undefined
                    )),
      ?assertEqual({error, badscope},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"users.testuser.boxes">>],
                     [],
                     undefined
                    )),
      ?assertEqual({ok, {undefined, [<<"all.users.testuser.boxes.fuu">>]}},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"users.testuser.boxes">>],
                     [<<"users.testuser.boxes.fuu">>],
                     undefined
                    )),
      ?assertEqual({ok, {undefined, [<<"read.users.testuser.boxes.fuu">>]}},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"read.users.testuser.boxes">>],
                     [<<"read.users.testuser.boxes.fuu">>],
                     undefined
                    )),
      ?assertEqual({ok, {undefined, [<<"read.users.testuser.boxes.fuu">>]}},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"all.users.testuser.boxes">>],
                     [<<"read.users.testuser.boxes.fuu">>],
                     undefined
                    )),
      ?assertEqual({error, badscope},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"read.users.testuser.boxes">>],
                     [<<"all.users.testuser.boxes.fuu">>],
                     undefined
                    )),
      ?assertEqual({error, badscope},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"read.users.testuser.boxes">>],
                     [<<"users.testuser.boxes.fuu">>],
                     undefined
                    )),
      ?assertEqual({error, badscope},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"users.testuser.boxes">>],
                     [<<"users.testuser">>],
                     undefined
                    )),
      ?assertEqual({error, badscope},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"users.testuser.boxes">>],
                     [<<"users.testuser.bar">>],
                     undefined
                    )),
      ?assertEqual({error, badscope},
                   oauth2_backend_mongopool:verify_scope(
                     [],
                     [<<"users.testuser.bar">>],
                     undefined
                    ))
  end.

associate_refresh_token_test(_) ->
  fun() ->
    RefreshToken = <<"Refresh-Token-Test">>,
    Context = [{<<"client">>, <<"Context-Access-Token-Test">>},
               {<<"resource_owner">>, <<"test_resource_owner">>},
               {<<"expiry_time">>, <<"1449319960">>}],
    AppCtx = #{pool => fuu},
    insert(fun(fuu, _, #{<<"_id">> := RefreshToken2,
                         <<"grant">> := Context2}) ->
               ?assertEqual(maps:from_list(Context), Context2),
               ?assertEqual(RefreshToken, RefreshToken2)
           end),
    {ok, AppCtx} = oauth2_backend_mongopool:associate_refresh_token(
                        RefreshToken, Context, AppCtx),
    find_one(#{<<"_id">> => RefreshToken,
               <<"grant">> => maps:from_list(Context)}),
    {ok, {AppCtx, Context2}} = oauth2_backend_mongopool:resolve_refresh_token(
                                 RefreshToken, AppCtx),
    ?assertEqual(maps:from_list(Context), maps:from_list(Context2)),
    delete(fun(fuu, _, Value) ->
               ?assertEqual(Value, #{<<"_id">> => RefreshToken})
           end),
    find_one(#{}),
    oauth2_backend_mongopool:revoke_refresh_token(RefreshToken, AppCtx),
    ?assertEqual(
      {error, notfound},
      oauth2_backend_mongopool:resolve_refresh_token(RefreshToken, AppCtx)
    )
  end.

associate_access_token_test(_) ->
  fun() ->
    AccessToken = <<"Access-Token-Test">>,
    Context = [{<<"client">>, <<"Context-Access-Token-Test">>},
               {<<"resource_owner">>, <<"test_resource_owner">>},
               {<<"expiry_time">>, <<"1449319960">>}],
    AppCtx = #{pool => fuu},
    insert(fun(fuu, _, #{<<"_id">> := AccessToken2,
                         <<"grant">> := Context2}) ->
               ?assertEqual(maps:from_list(Context), Context2),
               ?assertEqual(AccessToken, AccessToken2)
           end),
    {ok, AppCtx} = oauth2_backend_mongopool:associate_access_token(
                        AccessToken, Context, AppCtx),
    find_one(#{<<"_id">> => AccessToken,
               <<"grant">> => maps:from_list(Context)}),
    {ok, {AppCtx, Context2}} = oauth2_backend_mongopool:resolve_access_token(
                                AccessToken, AppCtx),
    ?assertEqual(maps:from_list(Context), maps:from_list(Context2)),
    find_one(#{}),
    delete(fun(fuu, _, Value) ->
               ?assertEqual(Value, #{<<"_id">> => AccessToken})
           end),
    oauth2_backend_mongopool:revoke_access_token(AccessToken, AppCtx),
    ?assertEqual(
      {error, notfound},
      oauth2_backend_mongopool:resolve_access_token(AccessToken, AppCtx)
    )
  end.

associate_access_code_test(_) ->
  fun() ->
    AccessCode = <<"Access-Code-Test">>,
    Context = [{<<"client">>, <<"Context-Access-Token-Test">>},
               {<<"resource_owner">>, <<"test_resource_owner">>},
               {<<"expiry_time">>, <<"1449319960">>}],
    AppCtx = #{pool => fuu},
    insert(fun(fuu, _, #{<<"_id">> := AccessCode2, <<"grant">> := Context2}) ->
               ?assertEqual(maps:from_list(Context), Context2),
               ?assertEqual(AccessCode, AccessCode2)
           end),
    {ok, AppCtx} = oauth2_backend_mongopool:associate_access_code(
                        AccessCode, Context, AppCtx),
    find_one(#{<<"_id">> => AccessCode,
               <<"grant">> => maps:from_list(Context)}),
    delete(fun(_, _, Value) ->
               ?assertEqual(Value, #{<<"_id">> => AccessCode})
           end),

    {ok, {AppCtx, Context2}} = oauth2_backend_mongopool:resolve_access_code(
                                 AccessCode, AppCtx),
    ?assertEqual(maps:from_list(Context), maps:from_list(Context2)),
    find_one(#{}),
    oauth2_backend_mongopool:revoke_access_code(AccessCode, AppCtx),
    ?assertEqual(
      {error, notfound},
      oauth2_backend_mongopool:resolve_access_code(AccessCode, AppCtx)
    )
  end.

authenticate_user_test(_SetupData) ->
  fun() ->
    UserId = <<"test-user-id">>,
    Password = <<"test-password">>,
    WrongUserId = <<"wrong-user-id">>,
    WrongPassword = <<"wrong-password">>,
    User = #{<<"_id">> => UserId, <<"password">> => Password,
             <<"status">> => <<"active">>},
    AppCtx = #{pool => fuu, backendctx => #{pool => fuu}},
    find_one(fun(fuu, _, Value) ->
               ?assertEqual(
                  #{<<"_id">> => UserId}, Value),
               User
           end),
    % check ok
    {ok, {AppCtx, #{<<"password">> := undefined}}} =
      oauth2_backend_mongopool:authenticate_user({UserId, Password}, AppCtx),
    % check badpass
    {error, badpass} =
      oauth2_backend_mongopool:authenticate_user(
        {UserId, WrongPassword}, AppCtx),
    find_one(fun(fuu, _, Value) ->
               ?assertEqual(#{<<"_id">> => WrongUserId}, Value),
               #{}
           end),
    % check notfound (user id doesn't exist)
    {error, notfound} = oauth2_backend_mongopool:authenticate_user(
        {WrongUserId, Password}, AppCtx),
    UserNotActive = User#{<<"status">> => <<"register">>},
    find_one(fun(fuu, _, Value) ->
                 ?assertEqual(
                    #{<<"_id">> => maps:get(<<"_id">>, UserNotActive)}, Value),
                 #{}
           end),
    % check notfound (user is not active)
    {error, notfound} = oauth2_backend_mongopool:authenticate_user(
        {UserId, Password}, AppCtx)
  end.

authenticate_client_test(_SetupData) ->
  fun() ->
    ClientId = <<"test-client-id">>,
    ClientSecret = <<"test-client_secret">>,
    WrongUserId = <<"wrong-client-id">>,
    WrongClientSecret = <<"wrong-client_secret">>,
    Client = #{<<"_id">> => ClientId, <<"client_secret">> => ClientSecret},
    AppCtx = #{pool => fuu, backendctx => #{pool => fuu}},
    find_one(fun(fuu, _, Value) ->
               ?assertEqual(#{<<"_id">> => ClientId}, Value),
               Client
           end),
    {ok, {AppCtx, #{<<"client_secret">> := undefined}}} =
      oauth2_backend_mongopool:authenticate_client(
        {ClientId, ClientSecret}, AppCtx),
    {error, badsecret} =
      oauth2_backend_mongopool:authenticate_client(
        {ClientId, WrongClientSecret}, AppCtx),
    find_one(fun(fuu, _, Value) ->
               ?assertEqual(Value, #{<<"_id">> => WrongUserId}),
               #{}
           end),
    {error, notfound} =
      oauth2_backend_mongopool:authenticate_client(
        {WrongUserId, ClientSecret}, AppCtx)
  end.

get_client_identity_test(_SetupData) ->
  fun() ->
    ClientId = <<"test-client-id">>,
    ClientSecret = <<"test-client_secret">>,
    WrongUserId = <<"wrong-client-id">>,
    Client = #{<<"_id">> => ClientId, <<"client_secret">> => ClientSecret},
    AppCtx = #{pool => fuu, backendctx => #{pool => fuu}},
    find_one(fun(fuu, _, Value) ->
               ?assertEqual(#{<<"_id">> => ClientId}, Value),
               Client
           end),
    {ok, {AppCtx, #{<<"client_secret">> := undefined}}} =
      oauth2_backend_mongopool:get_client_identity(ClientId, AppCtx),
    find_one(fun(fuu, _, Value) ->
               ?assertEqual(#{<<"_id">> => WrongUserId}, Value),
               #{}
           end),
    {error, notfound} =
      oauth2_backend_mongopool:get_client_identity(WrongUserId, AppCtx)
  end.

verify_redirection_uri_test(_SetupData) ->
  fun() ->
    AppCtx = #{pool => fuu},
    Uri = <<"http://fuu.bar">>,
    WrongUri = <<"http://wrong.uri">>,
    Client = #{<<"redirect_uri">> => Uri},
    {ok, AppCtx} = oauth2_backend_mongopool:verify_redirection_uri(
                            Client, Uri, AppCtx),
    % test empty redirect_uri
    {ok, AppCtx} = oauth2_backend_mongopool:verify_redirection_uri(
                        Client#{<<"redirect_uri">> => <<"">>}, <<"">>, AppCtx),
    {error, baduri} = oauth2_backend_mongopool:verify_redirection_uri(
                        Client, WrongUri, AppCtx)
  end.

verify_client_scope_test(_SetupData) ->
  fun() ->
    AppCtx = #{pool => fuu},
    Scope = [<<"foo.bar">>],
    WrongScope = [<<"wrong.scope">>],
    Client = #{<<"scope">> => Scope},
    FQScopes = [<<"all.foo.bar">>],
    {ok, {AppCtx, FQScopes}} = oauth2_backend_mongopool:verify_client_scope(
                              Client, Scope, AppCtx),
    {error, badscope} = oauth2_backend_mongopool:verify_client_scope(
                              Client, undefined, AppCtx),
    {error, badscope} = oauth2_backend_mongopool:verify_client_scope(
                              Client, [], AppCtx),
    {error, badscope} = oauth2_backend_mongopool:verify_client_scope(
                              Client, WrongScope, AppCtx),
    {error, badscope} = oauth2_backend_mongopool:verify_client_scope(
                              Client#{<<"scope">> => []}, Scope, AppCtx)
  end.

verify_resowner_scope_test(_SetupData) ->
  fun() ->
    AppCtx = #{pool => fuu},
    Scope = [<<"foo.bar">>],
    WrongScope = [<<"wrong.scope">>],
    User = #{<<"scope">> => Scope},
    FQScopes = [<<"all.foo.bar">>],
    {ok, {AppCtx, FQScopes}} = oauth2_backend_mongopool:verify_resowner_scope(
                              User, Scope, AppCtx),
    {error, badscope} = oauth2_backend_mongopool:verify_resowner_scope(
                              User, undefined, AppCtx),
    {error, badscope} = oauth2_backend_mongopool:verify_resowner_scope(
                              User, [], AppCtx),
    {error, badscope} = oauth2_backend_mongopool:verify_resowner_scope(
                              User, WrongScope, AppCtx),
    {error, badscope} = oauth2_backend_mongopool:verify_resowner_scope(
                              User#{<<"scope">> => []}, Scope, AppCtx)
  end.

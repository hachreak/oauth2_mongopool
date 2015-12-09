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
%%% @doc Esensub Worker - Tests.
%%% @end

-module(oauth2_backend_mongopool_tests).

-include_lib("eunit/include/eunit.hrl").

oauth2_backend_mongopool_test_() ->
  {setup,
    fun start/0,
    fun stop/1,
    fun (SetupData) ->
        [
         is_authorized_fail_expiry_time(SetupData),
         is_authorized_fail_scope(SetupData),
         is_authorized_ok_pass_1(SetupData),
         is_authorized_ok_pass_2(SetupData),
         verify_scope_test(SetupData),
         associate_refresh_token_test(SetupData),
         associate_access_token_test(SetupData),
         associate_access_code_test(SetupData)
        ]
    end
  }.

start() ->
  meck:new(mongopool_app, [no_link, passthrough, no_history, non_strict]),
  application:set_env(oauth2, backend, oauth2_backend_mongopool).

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

is_authorized_fail_expiry_time(_SetupData) ->
  fun() ->
      PermittedScope = <<"users.test.boxes">>,
      GetObjectScope = fun(_) -> [<<"users.test.boxes">>] end,
      DiffExpiryTime = -1,
      % prepare
      {Mega, Secs, _} = os:timestamp(),
      ExpiryTime = Mega * 1000000 + Secs + DiffExpiryTime,
      AccessToken = <<"test-ist-auth-access-token">>,
      Context = [
                 #{<<"">> => ""},
                 #{<<"">> => ""},
                 #{<<"expiry_time">> => ExpiryTime},
                 #{<<"">> => ""},
                 #{<<"scope">> => [PermittedScope]}
                 #{<<"">> => ""},
                 #{<<"">> => ""},
                 #{<<"">> => ""}
                ],
      find_one(#{<<"token">> => AccessToken, <<"grant">> => Context}),
      delete(fun(_, _, Value) ->
              ?assertEqual(Value, #{<<"token">> => AccessToken})
             end),
      ?assertException(
         throw, not_authorized,
         oauth2_backend_mongopool:is_authorized(AccessToken, GetObjectScope))
  end.

is_authorized_fail_scope(_SetupData) ->
  fun() ->
      PermittedScope = <<"users.test.boxes">>,
      GetObjectScope = fun(_) -> [<<"users.test">>] end,
      DiffExpiryTime = 1000000,
      % prepare
      {Mega, Secs, _} = os:timestamp(),
      ExpiryTime = Mega * 1000000 + Secs + DiffExpiryTime,
      AccessToken = <<"test-ist-auth-access-token">>,
      Context = [
                 #{<<"">> => ""},
                 #{<<"">> => ""},
                 #{<<"expiry_time">> => ExpiryTime},
                 #{<<"">> => ""},
                 #{<<"scope">> => [PermittedScope]}
                 #{<<"">> => ""},
                 #{<<"">> => ""},
                 #{<<"">> => ""}
                ],
      find_one(#{<<"token">> => AccessToken, <<"grant">> => Context}),
      delete(fun(_, _, Value) ->
              ?assertEqual(Value, #{<<"token">> => AccessToken})
             end),
      ?assertException(
         throw, not_authorized,
         oauth2_backend_mongopool:is_authorized(AccessToken, GetObjectScope))
  end.

is_authorized_ok_pass_1(_SetupData) ->
  fun() ->
      PermittedScope = <<"users.test.boxes">>,
      GetObjectScope = fun(_) -> [<<"users.test.boxes.fuu">>] end,
      DiffExpiryTime = 1000000,
      % prepare
      {Mega, Secs, _} = os:timestamp(),
      ExpiryTime = Mega * 1000000 + Secs + DiffExpiryTime,
      AccessToken = <<"test-ist-auth-access-token">>,
      Context = [
                 #{<<"">> => ""},
                 #{<<"">> => ""},
                 #{<<"expiry_time">> => ExpiryTime},
                 #{<<"">> => ""},
                 #{<<"scope">> => [PermittedScope]}
                 #{<<"">> => ""},
                 #{<<"">> => ""},
                 #{<<"">> => ""}
                ],
      find_one(#{<<"token">> => AccessToken, <<"grant">> => Context}),
      delete(fun(_, _, Value) ->
              ?assertEqual(Value, #{<<"token">> => AccessToken})
             end),
      ?assertEqual(
         oauth2_mongopool_utils:dbMap2OAuth2List(Context),
         oauth2_backend_mongopool:is_authorized(AccessToken, GetObjectScope))
  end.

is_authorized_ok_pass_2(_SetupData) ->
  fun() ->
      PermittedScope = <<"users.test.boxes">>,
      GetObjectScope = fun(_) -> [<<"users.test.boxes">>] end,
      DiffExpiryTime = 1000000,
      % prepare
      {Mega, Secs, _} = os:timestamp(),
      ExpiryTime = Mega * 1000000 + Secs + DiffExpiryTime,
      AccessToken = <<"test-ist-auth-access-token">>,
      Context = [
                 #{<<"">> => ""},
                 #{<<"">> => ""},
                 #{<<"expiry_time">> => ExpiryTime},
                 #{<<"">> => ""},
                 #{<<"scope">> => [PermittedScope]}
                 #{<<"">> => ""},
                 #{<<"">> => ""},
                 #{<<"">> => ""}
                ],
      find_one(#{<<"token">> => AccessToken, <<"grant">> => Context}),
      delete(fun(_, _, Value) ->
              ?assertEqual(Value, #{<<"token">> => AccessToken})
             end),
      ?assertEqual(
         oauth2_mongopool_utils:dbMap2OAuth2List(Context),
         oauth2_backend_mongopool:is_authorized(AccessToken, GetObjectScope))
  end.

verify_scope_test(_) ->
  fun() ->
      ?assertEqual({ok, {undefined, [<<"users.testuser.boxes">>]}},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"users.testuser.boxes">>],
                     [<<"users.testuser.boxes">>],
                     undefined
                    )),
      ?assertEqual({ok, {undefined, [<<"users.testuser.boxes.fuu">>]}},
                   oauth2_backend_mongopool:verify_scope(
                     [<<"users.testuser.boxes">>],
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
                    ))
  end.

associate_refresh_token_test(_) ->
  fun() ->
    RefreshToken = <<"Refresh-Token-Test">>,
    Context = [#{<<"client">> => <<"Context-Access-Token-Test">>},
               #{<<"resource_owner">> => <<"test_resource_owner">>},
               #{<<"expiry_time">> => <<"1449319960">>}],
    insert(fun(_, _, Value) ->
               ?assertEqual(
                  Value, #{<<"token">> => RefreshToken,
                           <<"_id">> => RefreshToken, <<"grant">> => Context})
           end),
    {ok, undefined} = oauth2_backend_mongopool:associate_refresh_token(
                        RefreshToken, Context, undefined),
    find_one(#{<<"token">> => RefreshToken, <<"grant">> => Context}),
    ?assertEqual(
      {ok, {undefined, oauth2_mongopool_utils:dbMap2OAuth2List(Context)}},
      oauth2_backend_mongopool:resolve_refresh_token(RefreshToken, undefined)
    ),
    delete(fun(_, _, Value) ->
               ?assertEqual(Value, #{<<"token">> => RefreshToken})
           end),
    find_one(#{}),
    oauth2_backend_mongopool:revoke_refresh_token(RefreshToken, undefined),
    ?assertEqual(
      {error, notfound},
      oauth2_backend_mongopool:resolve_refresh_token(RefreshToken, undefined)
    )
  end.

associate_access_token_test(_) ->
  fun() ->
    AccessToken = <<"Access-Token-Test">>,
    Context = [#{<<"client">> => <<"Context-Access-Token-Test">>},
               #{<<"resource_owner">> => <<"test_resource_owner">>},
               #{<<"expiry_time">> => <<"1449319960">>}],
    insert(fun(_, _, Value) ->
               ?assertEqual(
                  Value, #{<<"token">> => AccessToken,
                           <<"_id">> => AccessToken, <<"grant">> => Context})
           end),
    {ok, undefined} = oauth2_backend_mongopool:associate_access_token(
                        AccessToken, Context, undefined),
    find_one(#{<<"token">> => AccessToken, <<"grant">> => Context}),
    ?assertEqual(
      {ok, {undefined, oauth2_mongopool_utils:dbMap2OAuth2List(Context)}},
      oauth2_backend_mongopool:resolve_access_token(AccessToken, undefined)
    ),
    find_one(#{}),
    delete(fun(_, _, Value) ->
               ?assertEqual(Value, #{<<"token">> => AccessToken})
           end),
    oauth2_backend_mongopool:revoke_access_token(AccessToken, undefined),
    ?assertEqual(
      {error, notfound},
      oauth2_backend_mongopool:resolve_access_token(AccessToken, undefined)
    )
  end.

associate_access_code_test(_) ->
  fun() ->
    AccessCode = <<"Access-Code-Test">>,
    Context = [#{<<"client">> => <<"Context-Access-Token-Test">>},
               #{<<"resource_owner">> => <<"test_resource_owner">>},
               #{<<"expiry_time">> => <<"1449319960">>}],
    insert(fun(_, _, Value) ->
               ?assertEqual(
                  Value, #{<<"token">> => AccessCode,
                           <<"_id">> => AccessCode, <<"grant">> => Context})
           end),
    {ok, undefined} = oauth2_backend_mongopool:associate_access_code(
                        AccessCode, Context, undefined),
    find_one(#{<<"token">> => AccessCode, <<"grant">> => Context}),
    delete(fun(_, _, Value) ->
               ?assertEqual(Value, #{<<"token">> => AccessCode})
           end),
    ?assertEqual(
      {ok, {undefined, oauth2_mongopool_utils:dbMap2OAuth2List(Context)}},
      oauth2_backend_mongopool:resolve_access_code(AccessCode, undefined)
    ),
    find_one(#{}),
    oauth2_backend_mongopool:revoke_access_code(AccessCode, undefined),
    ?assertEqual(
      {error, notfound},
      oauth2_backend_mongopool:resolve_access_code(AccessCode, undefined)
    )
  end.

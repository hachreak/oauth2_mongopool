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
%%% @doc Oauth2 mongopool users - Tests.
%%% @end

-module(oauth2_mongopool_users_tests).

-include_lib("eunit/include/eunit.hrl").

oauth2_mongopool_users_test_() ->
  {setup,
    fun start/0,
    fun stop/1,
    fun (SetupData) ->
        [
         add_resowner_test(SetupData),
         delete_resowner_test(SetupData),
         get_resowner_test(SetupData)
        ]
    end
  }.

start() ->
  meck:new(mongopool_app, [no_link, passthrough, no_history, non_strict]),
  meck:new(confirmator, [no_link, passthrough, no_history, non_strict]),
  meck:new(pushmail, [no_link, passthrough, no_history, non_strict]),
  application:set_env(oauth2, backend, oauth2_backend_mongopool),
  application:set_env(confirmator, backend, confirmator_mongopool).

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
  meck:unload(mongopool_app),
  meck:validate(confirmator),
  meck:unload(confirmator),
  meck:validate(pushmail),
  meck:unload(pushmail).


add_resowner_test(_SetupData) ->
  fun() ->
    UserId = <<"test-user">>,
    Password = <<"test-password">>,
    Email = <<"test@fuu.it">>,
    Scope = [<<"users.test-user">>],
    Token = <<"registration-token">>,
    AppCtx = #{pool => fuu, cfgctx => test, pmctx => test},
    meck:expect(confirmator, register, 2,
                fun(MyUserId, CFGctx) ->
                    ?assertEqual(MyUserId, UserId),
                    ?assertEqual(CFGctx, maps:get(cfgctx, AppCtx)),
                    {ok, {CFGctx, Token}}
                end),
    meck:expect(pushmail, send, 2,
               fun(_Mail, PMctx) ->
      ?assertEqual(PMctx, maps:get(pmctx, AppCtx)),
      {ok, PMctx}
    end),
    insert(fun(fuu, _, Value) ->
               ?assertEqual(Value,
                            #{<<"_id">> => UserId,
                              <<"username">> => UserId,
                              <<"password">> => Password,
                              <<"email">> => Email,
                              <<"status">> => <<"register">>,
                              <<"scope">> => Scope })
           end),
    {ok, {AppCtx, Token}} = oauth2_mongopool_users:add_resowner(
      UserId, Password, Email, AppCtx),
    {ok, {AppCtx, Token}} = oauth2_mongopool_users:add_resowner(
      UserId, Password, Email, Scope, AppCtx)
  end.

delete_resowner_test(_SetupData) ->
  fun() ->
    UserId = <<"test-user">>,
    AppCtx = #{pool => fuu},
    delete(fun(fuu, _, Value) ->
               ?assertEqual(Value, #{<<"_id">> => UserId})
           end),
    {ok, AppCtx} = oauth2_mongopool_users:delete_resowner(
      UserId, AppCtx)
  end.

get_resowner_test(_SetupData) ->
  fun() ->
    UserId = <<"test-user">>,
    AppCtx = #{pool => fuu},
    User = #{<<"_id">> => UserId},
    find_one(fun(fuu, _, Value) ->
               ?assertEqual(Value, #{<<"_id">> => UserId}),
               User
           end),
    {ok, {AppCtx, User}} = oauth2_mongopool_users:get_resowner(
      UserId, AppCtx),
    find_one(#{}),
    ?assertException(
       throw, notfound, oauth2_mongopool_users:get_resowner(UserId, AppCtx))
  end.

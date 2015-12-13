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

-module(oauth2_mongopool_clients_tests).

-include_lib("eunit/include/eunit.hrl").

oauth2_backend_mongopool_test_() ->
  {setup,
    fun start/0,
    fun stop/1,
    fun (SetupData) ->
        [
         delete_client_test(SetupData),
         get_client_test(SetupData)
        ]
    end
  }.

start() ->
  meck:new(mongopool_app, [no_link, passthrough, no_history, non_strict]),
  application:set_env(oauth2, backend, oauth2_mongopool_clients).

find_one(Fun) when is_function(Fun) ->
  meck:expect(mongopool_app, find_one, 3, Fun);
find_one(Return) ->
  meck:expect(mongopool_app, find_one, 3, fun(_A, _B, _C) -> Return end).

delete(Fun) when is_function(Fun) ->
  meck:expect(mongopool_app, delete, 3, Fun);
delete(Return) ->
  meck:expect(mongopool_app, delete, 3, fun(_A, _B, _C) -> Return end).

stop(_Pid) ->
  meck:validate(mongopool_app),
  meck:unload(mongopool_app).


delete_client_test(_SetupData) ->
  fun() ->
    ClientId = <<"test-client">>,
    AppCtx = #{pool => fuu},
    delete(fun(fuu, _, Value) ->
               ?assertEqual(Value, #{<<"_id">> => ClientId})
           end),
    {ok, AppCtx} = oauth2_mongopool_clients:delete_client(
      ClientId, AppCtx)
  end.

get_client_test(_SetupData) ->
  fun() ->
    ClientId = <<"test-client">>,
    AppCtx = #{pool => fuu},
    Client = #{<<"_id">> => ClientId},
    find_one(fun(fuu, _, Value) ->
               ?assertEqual(Value, #{<<"_id">> => ClientId}),
               Client
           end),
    {ok, {AppCtx, Client}} = oauth2_mongopool_clients:get_client(
      ClientId, AppCtx),
    find_one(#{}),
    {error, notfound} = oauth2_mongopool_clients:get_client(ClientId, AppCtx)
  end.

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
%%% @doc Utilities.
%%% @end

-module(oauth2_mongopool_utils_tests).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-include_lib("eunit/include/eunit.hrl").

oauth2_mongopool_utils_test_() ->
  {setup,
    fun start/0,
    fun stop/1,
    fun (SetupData) ->
        [
          get_scope(SetupData),
          get_cid(SetupData),
          get_userid(SetupData),
          copy_if_exists(SetupData)
        ]
    end
  }.

start() ->
  ok.

stop(_) ->
  ok.

get_scope(_) ->
  fun() ->
      ?assertEqual(
         fuu, oauth2_mongopool_utils:get_scope([{<<"scope">>, fuu}])),
      ?assertEqual(
         fu, oauth2_mongopool_utils:get_scope([{a,b}, {<<"scope">>, fu}])),
      ?assertEqual(
         fu, oauth2_mongopool_utils:get_scope([{<<"scope">>, fu}, {a,b}]))
  end.

get_cid(_) ->
  fun() ->
      ?assertEqual(
         fuu, oauth2_mongopool_utils:get_cid(
                [{<<"client">>, #{<<"_id">> => fuu}}])),
      ?assertEqual(
         fu, oauth2_mongopool_utils:get_cid(
               [{a,b}, {<<"client">>, #{<<"_id">> => fu}}])),
      ?assertEqual(
         fu, oauth2_mongopool_utils:get_cid(
               [{<<"client">>, #{<<"_id">> => fu}}, {a,b}])),
      ?assertEqual(undefined, oauth2_mongopool_utils:get_cid([]))
  end.

get_userid(_) ->
  fun() ->
      ?assertEqual(
         fuu, oauth2_mongopool_utils:get_userid(
                [{<<"resource_owner">>, #{<<"_id">> => fuu}}])),
      ?assertEqual(
         fu, oauth2_mongopool_utils:get_userid(
               [{a,b}, {<<"resource_owner">>, #{<<"_id">> => fu}}])),
      ?assertEqual(
         fu, oauth2_mongopool_utils:get_userid(
               [{<<"resource_owner">>, #{<<"_id">> => fu}}, {a,b}])),
      ?assertEqual(undefined, oauth2_mongopool_utils:get_userid([]))
  end.

copy_if_exists(_) ->
  fun() ->
      ?assertEqual(
        #{a => b},
        oauth2_mongopool_utils:copy_if_exists(c, c, #{d => e}, #{a => b})),
      ?assertEqual(
        #{a => b},
        oauth2_mongopool_utils:copy_if_exists(a, a, #{a => b}, #{})),
      ?assertEqual(
        #{a => b, c => d},
        oauth2_mongopool_utils:copy_if_exists(a, a, #{a => b}, #{c => d})),
      ?assertEqual(
        #{a => b, c => d},
        oauth2_mongopool_utils:copy_if_exists(
          a, a, #{a => b}, #{a => e, c => d})),
      ?assertEqual(
        #{a => e, a2 => b, c => d},
        oauth2_mongopool_utils:copy_if_exists(
          a, a2, #{a => b}, #{a => e, c => d}))
  end.

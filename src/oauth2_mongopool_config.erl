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
%%% @doc Application configuration.
%%% @end

-module(oauth2_mongopool_config).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

%% API exports
-export([backend/0, table/2]).

-spec table(atom(), term()) -> binary() | no_return().
table(Id, Default) -> get_config(Id, Default).

%% @doc Gets the sendmail backend.
-spec backend() -> atom().
backend() -> get_config(backend, oauth2_mongopool_backend_default).

%%% Private functions ================================================

get_config(Key, Default) ->
  case application:get_env(oauth2_mongopool, Key) of
    undefined   -> Default;
    {ok, Value} -> Value
  end.

-spec get_config(atom()) -> binary() | no_return().
get_config(Key) ->
  case application:get_env(oauth2_mongopool, Key) of
    undefined   -> throw({missing_config, Key});
    {ok, Value} -> Value
  end.

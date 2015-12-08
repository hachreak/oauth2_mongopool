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
%%% @doc Utilities.
%%% @end

-module(oauth2_mongopool_utils).

-export([dbMap2OAuth2List/1]).

% @doc Note: [map] -> [proplist]
%   if you write list [{K1,V1}, {K2,V2}] into the mongodb
%   when you'll read, you have a map as [#{K1 => V1}, #{K2 => V2}]! T_T
%   This function make the transformation back.
% @end
dbMap2OAuth2List(Data) ->
  lists:concat(
    [
     case is_list(X) of
       true -> X;
       false ->
         case is_map(X) of
           true -> maps:to_list(X);
           false -> X
         end
     end || X <- Data
    ]).

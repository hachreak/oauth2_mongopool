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
%%% @doc this module define the users, clients backend.
%%%    In other words, the only things that oauth2_mongopool need to know
%%%    about users and clients.
%%% @end

-module(oauth2_mongopool_backend).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-export_type([userid/0, password/0, clientid/0, secret/0]).

-type appctx()   :: oauth2:appctx().
-type userid()   :: binary().
-type password() :: binary().
-type clientid() :: binary().
-type secret()   :: binary().

-callback authenticate_user(userid(), password(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound | badpass}.

-callback get_client(clientid(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound}.

-callback authenticate_client(clientid(), secret(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound | badpass}.

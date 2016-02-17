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

-type appctx()   :: oauth2:appctx().
-type user()     :: oauth2:user().
-type client()   :: oauth2:client().
-type clientid() :: binary().

-callback get_user(user(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound | badpass}.

-callback get_client_identity(clientid(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound}.

-callback get_client(client(), appctx()) ->
  {ok, {appctx(), term()}} | {error, notfound | badpass}.

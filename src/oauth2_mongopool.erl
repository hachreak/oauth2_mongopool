-module('oauth2_mongopool').

% FIXME deprecated!
-behaviour(application).

%% API exports
-export([start/2, stop/1, init/0, init/1, init/2]).

%%%_ * Types -----------------------------------------------------------

-export_type([appctx/0, backendctx/0]).

-type pool()       :: term().
-type backendctx() :: term().
-type appctx()     :: #{pool => pool(), backendctx => backendctx()}.

%%====================================================================
%% API functions
%%====================================================================

-spec start(application:start_type(), term()) ->
    ok | {error, term()}.
start(_StartType, _StartArgs) ->
  ok.

-spec stop(term()) -> ok.
stop(_State) ->
  ok.

-spec init() -> {ok, appctx()} | {error, term()}.
init() ->
  init(load_appctx()).

-spec init(backendctx()) ->  {ok, appctx()} | {error, term()}.
init(BackendCtx) ->
  init(load_appctx(), BackendCtx).

-spec init(pool(), backendctx()) -> {ok, appctx()} | {error, term()}.
init(Pool, BackendCtx) ->
  application:ensure_all_started(mongopool),
  {ok, #{pool => Pool, backendctx => BackendCtx}}.

%%====================================================================
%% Internal functions
%%====================================================================

-spec load_appctx() -> appctx().
load_appctx() ->
  {ok, Pool} = application:get_env(oauth2_mongopool, pool),
  Pool.

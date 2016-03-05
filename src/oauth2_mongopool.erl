-module('oauth2_mongopool').

% FIXME deprecated!
-behaviour(application).

%% API exports
-export([start/2, stop/1, init/0, init/1]).

%%%_ * Types -----------------------------------------------------------

-type appctx()   :: oauth2:appctx().

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

-spec init() ->  {ok, appctx()} | {error, term()}.
init() ->
  {ok, Pool} = application:get_env(oauth2_mongopool, pool),
  init(Pool).

-spec init(binary()) -> {ok, appctx()} | {error, term()}.
init(Pool) ->
  application:ensure_all_started(mongopool),
  {ok, #{pool => Pool}}.

%%====================================================================
%% Internal functions
%%====================================================================

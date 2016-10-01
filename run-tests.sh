#!/bin/sh

DIR=`dirname $0`

# wait mongodb is up
sleep 5

# start tests
cd $DIR
./utils/rebar3 do compile, eunit, cover -v

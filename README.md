oauth2_mongopool
=====

[![Build Status](https://travis-ci.org/hachreak/oauth2_mongopool.svg?branch=master)](https://travis-ci.org/hachreak/oauth2_mongopool)

A implementation of an [OAuth2](https://github.com/kivra/oauth2) backend with
persistence on `MongoDB` made with
[mongopool](https://github.com/hachreak/mongopool).

Configuration
-------------

```erlang
[
  {mongopool, [
    {pools, [
      {mypool, [
        {size, 10},
        {max_overflow, 30}
      ], [
        {database, <<"mydb">>},
        {hostname, dbserver},
        {login, "myuser"},
        {password, "mypassword"},
        {w_mode, safe}
      ]}
    ]}
  ]},
  {confirmator, [
    {backend, confirmator_mongopool}
  ]},
  {confirmator_mongopool, [
    {pool, mypool},
    {table, <<"confirmator">>}
  ]},
  {pushmail, [
    {backend, pushmail_backend_error_logger}
  ]},
  {oauth2_mongopool, [
    {pool, mypool}
  ]},
  {oauth2, [
    {backend, oauth2_backend_mongopool}
  ]}
]
```

Usage
-----

After you configure [oauth2](https://github.com/kivra/oauth2) and
[mongopool](https://github.com/hachreak/mongopool) as wrote before, you can
start the backend to ensure that `mongopool` is started.

```erlang
application:ensure_all_started(oauth2_mongopool).
{ok, AppCtx} = oauth2_mongopool:init().
```

The `AppCtx` is the application context used when you call `oauth2` functions.

E.g. to verify the access token:

```erlang
case oauth2:verify_access_token(<<mytoken>>, AppCtx) of
  {ok, } -> true;
  {error, _ErrType} -> false
end
```

Build
-----

    $ utils/rebar3 compile

Tests
-----

    $ ./utils/rebar3 eunit

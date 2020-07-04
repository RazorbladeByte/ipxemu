Users of Wine (http://www.winehq.org/) may need to set the
WINEDLLOVERRIDES environment variable before launching a program.

For example, suppose one has a program `Foo' installed in `/opt/foo',
and copied `wsock32.dll' to `/opt/foo/wsock32.dll'. Then, to run the
program so that `wsock32.dll' is used, one may enter the following
commands in a terminal:
    $ cd /opt/foo
    $ export WINEDLLOVERRIDES=wsock32=n
    $ wine Foo

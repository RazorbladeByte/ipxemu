@echo off
rem Author: Jelle Geerts
rem
rem Usage of the works is permitted provided that this instrument is
rem retained with the works, so that any entity that uses the works is
rem notified of this instrument.
rem
rem DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.

setlocal
set exit_with_err=1

set config=-O -g -DDEBUG

set CFLAGS=%CFLAGS% ^
-Wall -Wextra -Werror -Wshadow -Wpointer-arith -Wcast-align ^
-Wwrite-strings -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls ^
-Wnested-externs -Wstrict-prototypes -Wformat=2 -Wundef ^
-pedantic -Wa,--fatal-warnings

set testbin=conftest.exe

gcc %CFLAGS% %config% -I src ^
src\conftest.c ^
-o "%testbin%" || goto :exit

".\%testbin%" || goto :exit

set exit_with_err=0

:exit
if exist "%testbin%" del "%testbin%"

if not "%exit_with_err%" == "0" ( \ 2>nul ) else ( cd . )

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

if not "%1" == "release" goto :debug
echo Compiling release build ...
set build=release
shift
goto :cont
:debug
echo Compiling debug build ...
set build=debug
if "%1" == "debug" shift
:cont

call conftest.bat >nul || goto :exit

set CFLAGS=%CFLAGS% ^
-Wall -Wextra -Werror -Wshadow -Wpointer-arith -Wcast-align ^
-Wwrite-strings -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls ^
-Wnested-externs -Wstrict-prototypes -Wformat=2 -Wundef ^
-pedantic -Wa,--fatal-warnings

if not exist _build\targets\thipx32 mkdir _build\targets\thipx32 || goto :exit
if not exist _build\targets\wsock32 mkdir _build\targets\wsock32 || goto :exit
if not exist _build\targets\win_9x-nt4_dpwsockx_patch mkdir _build\targets\win_9x-nt4_dpwsockx_patch || goto :exit
if not exist _build\targets\warcraft_2_bne_bugfix mkdir _build\targets\warcraft_2_bne_bugfix || goto :exit

rem ###########################################################################
rem # Begin target `wsock32.dll'.                                             #
rem ###########################################################################

if not "%build%" == "release" goto :debug
set config=-O3 -s -DNDEBUG
goto :cont
:debug
set config=-O -g -DDEBUG
:cont

windres -I src ^
src\targets\wsock32\wsock32.rc ^
_build\targets\wsock32\wsock32.rc.o || goto :exit

gcc %CFLAGS% %config% -I src ^
src\targets\wsock32\wsock32.c ^
src\targets\wsock32\wsock32.def ^
src\targets\wsock32\socktable.c ^
src\targets\wsock32\enum_protocols_template.c ^
_build\targets\wsock32\wsock32.rc.o ^
-shared ^
-l my_mswsock ^
-l my_ws2_32 ^
-L lib ^
-o wsock32.dll || goto :exit

rem ###########################################################################
rem # End target `wsock32.dll'.                                               #
rem ###########################################################################

rem ###########################################################################
rem # Begin target `thipx32.dll'.                                             #
rem ###########################################################################

if not "%build%" == "release" goto :debug
set config=-O3 -s -DNDEBUG
goto :cont
:debug
set config=-O -g -DDEBUG
:cont

windres -I src ^
src\targets\thipx32\thipx32.rc ^
_build\targets\thipx32\thipx32.rc.o || goto :exit

gcc %CFLAGS% %config% -I src ^
src\targets\thipx32\thipx32.c ^
src\targets\thipx32\thipx32.def ^
_build\targets\thipx32\thipx32.rc.o ^
-shared ^
-l my_ws2_32 ^
-L lib ^
-o thipx32.dll || goto :exit

rem ###########################################################################
rem # End target `thipx32.dll'.                                               #
rem ###########################################################################

rem ###########################################################################
rem # Begin target `win_9x-nt4_dpwsockx_patch.exe'.                           #
rem ###########################################################################

if not "%build%" == "release" goto :debug
set config=-O3 -s -DNDEBUG -mwindows
goto :cont
:debug
set config=-O -g -DDEBUG
:cont

windres -I src ^
src\targets\win_9x-nt4_dpwsockx_patch\win_9x-nt4_dpwsockx_patch.rc ^
_build\targets\win_9x-nt4_dpwsockx_patch\win_9x-nt4_dpwsockx_patch.rc.o || goto :exit

gcc %CFLAGS% %config% ^
src\targets\win_9x-nt4_dpwsockx_patch\win_9x-nt4_dpwsockx_patch.c ^
_build\targets\win_9x-nt4_dpwsockx_patch\win_9x-nt4_dpwsockx_patch.rc.o ^
-l gdi32 ^
-o win_9x-nt4_dpwsockx_patch.exe || goto :exit

rem ###########################################################################
rem # End target `win_9x-nt4_dpwsockx_patch.exe'.                             #
rem ###########################################################################

rem ###########################################################################
rem # Begin target `warcraft_2_bne_bugfix.exe'.                               #
rem ###########################################################################

if not "%build%" == "release" goto :debug
set config=-O3 -s -DNDEBUG
goto :cont
:debug
set config=-O -g -DDEBUG
:cont

windres -I src ^
src\targets\warcraft_2_bne_bugfix\warcraft_2_bne_bugfix.rc ^
_build\targets\warcraft_2_bne_bugfix\warcraft_2_bne_bugfix.rc.o || goto :exit

gcc %CFLAGS% %config% ^
src\targets\warcraft_2_bne_bugfix\warcraft_2_bne_bugfix.c ^
src\targets\warcraft_2_bne_bugfix\confirm\confirm.c ^
_build\targets\warcraft_2_bne_bugfix\warcraft_2_bne_bugfix.rc.o ^
-o warcraft_2_bne_bugfix.exe || goto :exit

rem ###########################################################################
rem # End target `warcraft_2_bne_bugfix.exe'.                                 #
rem ###########################################################################

set exit_with_err=0

:exit
if not "%exit_with_err%" == "0" ( \ 2>nul ) else ( cd . )

rem =============================================================================
rem Vader Modular Fuzzer (VMF)
rem Copyright (c) 2021-2025 The Charles Stark Draper Laboratory, Inc.
rem <vmf@draper.com>
rem
rem This program is free software: you can redistribute it and/or modify
rem it under the terms of the GNU General Public License version 2 (only) as 
rem published by the Free Software Foundation.
rem  
rem This program is distributed in the hope that it will be useful,
rem but WITHOUT ANY WARRANTY; without even the implied warranty of
rem MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
rem GNU General Public License for more details.
rem  
rem You should have received a copy of the GNU General Public License
rem along with this program. If not, see <http://www.gnu.org/licenses/>.
rem  
rem @license GPL-2.0-only <https://spdx.org/licenses/GPL-2.0-only.html>
rem ===========================================================================*/
rem example of building the devkit with alternate options (specifically -md)
rem configure --help is usefull, and shows --enable-symbols in particular would be helpfull
rem in particular when building with symbols it would be good to not include the prebuilts. 
rem call configure --enable-symbols --without-prebuilds sdk,sdk:build,sdk:host -- --buildtype=release --backend ninja "-Db_vscrt=md" "-Ddevkits=gum,gumjs"
rem Usage: build-devkit-md.bat <fridaTag> eg. build-devkit-md.bat 16.4.8
rem Assumes tar installed, such as with: winget install 7Zip
rem
if %1.==. GOTO skipGIT
git clone -b %1 https://github.com/frida/frida-gum.git 
:skipGIT
cd frida-gum
call configure -- --buildtype=release --backend ninja "-Db_vscrt=md" "-Ddevkits=gum,gumjs"
call make
cd build\gum\devkit
del /q ..\..\..\..\frida-gum-devkit-%1-windows-x86_64_local.tar*
7z a -ttar -so foo.tar * | 7z a -txz -si ..\..\..\..\frida-gum-devkit-%1-windows-x86_64_local.tar.xz
cd ..\..\..\..

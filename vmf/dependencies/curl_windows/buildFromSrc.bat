rem 
rem These are the instructions for building the CMAKE Visual Studio targets 
rem There are several binary distributions https://curl.se/download.html#Win64 
rem and to ensure consistency with VMF are distributing an archive built consistently
rem with the VMF CMake settings. 
rem This procedure records the build steps to recreate that embedded archive
rem Usage: build-devkit-md.bat curl-8_9_1
rem 
rem Requires 7Zip installed such as with: winget install 7Zip
rem
@echo on
if %1.==. GOTO skipGIT
git clone -b %1 https://github.com/curl/curl.git
echo %1>VMF_TAG.txt
:skipGIT
set /P VMFCURL=<VMF_TAG.txt
cd curl
call buildconf
mkdir build
cd build
cmake -DBUILD_STATIC_LIBS=On "-DCMAKE_INSTALL_PREFIX=%CD%\curl_bin" "-GVisual Studio 17 2022" ..
cmake --build . --target=install --config=Release
cd curl_bin
"C:\Program Files\7-Zip\7z" a -tzip ..\..\..\%VMFCURL%-vmf.zip *
cd ..\..\..


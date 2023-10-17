# VMF External Projects

## Overview

VMF contains a collection of different tools which attempts to build a unified 
experience for a given end user attempting to fuzz software. As
such, there are numeous third party efforts being utilized by VMF. These are
primarily included as `git` submodules, but some are also just used as system
or locally installed packages.

This document intends to track the included third party tools, and their
associated licenses in order to ensure all license conditions are being met, and
no incompatibly licensed tools are being included.

## Submodules

The most common, and potentially complicated example of project inclusion in
VMF is the `git` submodule. The projects included in this way are built as
external dependencies by the `CMake` build system, and their build artifacts
required by VMF are installed into the `external` subdirectory of VMF's
repository.  See [vmf/submodules/README](../vmf/submodules/README.md) for more information 
on building the submodules, and [build_system.md](build_system.md) for information
on how to add a new submodule to VMF.

There are two kinds of inclusion currently being performed:

- Inclusion as a library with available header files
- Inclusion at a source level by copying portions of a third-party source file
  into VMF

### Projects included at a library level

| Project                                             | Version                      | License    |
| --------------------------------------------------- | ---------------------------- | ---------- |
| [AFL++](https://github.com/AFLplusplus/AFLplusplus) | 4.01a-a2eb1f14               | [Apache 2.0](https://github.com/AFLplusplus/AFLplusplus/blob/stable/LICENSE) |
| [googletest](https://github.com/google/googletest)  | release-1.8.0-2963-8d51dc50  | [BSD Clause 3 New or Revised](https://github.com/google/googletest/blob/main/LICENSE) |
| [yaml-cpp](https://github.com/jbeder/yaml-cpp)      | yaml-cpp-0.7.0-31-987a6042   | [MIT](https://github.com/jbeder/yaml-cpp/blob/master/LICENSE) |
| [plog](https://github.com/SergiusTheBest/plog)      | 1.1.9-d60df3a1               | [MIT](https://github.com/SergiusTheBest/plog/blob/master/LICENSE) |
| [LibAFL-legacy](https://github.com/AFLplusplus/LibAFL-legacy) | 8b399178           | [Apache 2.0](https://github.com/AFLplusplus/LibAFL-legacy/blob/dev/LICENSE) |
| [restclient-cpp](https://github.com/mrtazz/restclient-cpp) | 0.5.2-c4683b21        | [MIT](https://github.com/mrtazz/restclient-cpp/blob/master/LICENSE) |
| [json11](https://github.com/dropbox/json11)         | head-2df9473f                | [MIT](https://github.com/dropbox/json11/blob/master/LICENSE.txt) |


### Projects included at a source level

| Project                                                       | Version   | License |
| ------------------------------------------------------------- | --------- | ------- |
| [LibAFL-legacy](https://github.com/AFLplusplus/LibAFL-legacy) | 8b399178 | [Apache 2.0](https://github.com/AFLplusplus/LibAFL-legacy/blob/dev/LICENSE) |
| [Klee ktest](https://github.com/klee/klee/) | 1.0 | [University of Illinois/NCSA Open Source License](https://github.com/klee/klee/blob/master/LICENSE.TXT) |
| [uthash](http://troydhanson.github.io/uthash/) |   2.1.0          | [BSD Revised](http://troydhanson.github.io/uthash/license.html)

## Installed Packages

A classic example of this is the `ln` Linux tool for making links to files, or the `stdio.h` C header for enabling printing to `STDOUT` and reading from `STDIN`.

Enumeration of these installations is for record keeping only:

| Package            | Installation type |
| ------------------ | ----------------- |
| afl++              | apt               |
| afl++-clang        | apt               |
| afl++-doc          | apt               |
| ca-certificates    | apt               |
| curl               | apt               |
| gdb                | apt               |
| gnupg              | apt               |
| libcurl-4-openssl-dev | apt            |
| lsb-core           | apt               |
| lsb-release        | apt               |
| graphviz           | apt               |
| clang-12           | apt               |
| doxygen            | apt               |
| llvm-12            | apt               |
| python3-dev        | apt               |
| python3-pip        | apt               |
| python3-setuptools | apt               |
| build-essential    | apt               |
| cmake              | apt               |
| lief               | pip               |

These packages need to be installed in order to build and run VMF.

### KLEE

`klee` must be installed and in your `$PATH` order to use the `KleeInitialization` 
module, which generates an initial corpus/seeds using symbolic execution. The KLEE 
team maintains [instructions to build KLEE from source](http://klee.github.io/build-llvm11/); 
however, we have found that specific versions of requirements such as LLVM may be mutually 
exclusive or difficult to manage in parallel with versions that are commonly available. As 
a result, we suggest [running KLEE in Docker](http://klee.github.io/docker/) with VMF 
instead. See the [docker/README.md](../docker/README.md) for information for building VMF 
with Klee in Docker.

## CDMS external projects

The distributed fuzzing Campaign Data Management Server (CDMS) depends on many different packages 
and libraries. Similar to VMF dependencies, there are two kinds of inclusion currently being performed:

- Inclusion as a Java Archive (.jar) file
- Inclusion at a source level by copying portions of a third-party package into CDMS

### Projects included at a library level

Build artifacts for these dependencies are included as Java Archive (.jar) files

| Project                                              | Version           | License    |
| ---------------------------------------------------- | ----------------- | ---------- |
| [Gson](https://github.com/google/gson)               | gson-parent-2.10.1 | [Apache 2.0](https://github.com/google/gson/blob/gson-parent-2.10.1/LICENSE)   |
| [ibatis](https://github.com/mybatis/ibatis-2)        | 2.5.0              | [Apache 2.0](https://github.com/mybatis/ibatis-2/blob/master/LICENSE)         |
| [sqlite-jdbc](https://github.com/xerial/sqlite-jdbc) | 3.43.0.0           | [Apache 2.0](https://github.com/xerial/sqlite-jdbc/blob/3.43.0.0/LICENSE)       |

### Projects included at a source level

| Project                                                       | Version    | License |
| ------------------------------------------------------------- | ---------- | ------- |
| [JQuery](https://github.com/jquery/jquery/tree/3.7.1)         | 3.7.1     | [MIT](https://github.com/jquery/jquery/blob/3.7.1/LICENSE.txt)|
| [JQuery UI](https://github.com/jquery/jquery-ui/tree/1.8.1)   | 1.8.1	     | Dual licensed under the [MIT](https://github.com/jquery/jquery-ui/blob/1.8.1/MIT-LICENSE.txt) and [GPL](https://github.com/jquery/jquery-ui/blob/1.8.1/GPL-LICENSE.txt) licenses |
| [JQuery UI](https://github.com/jquery/jquery-ui/tree/1.13.2)  | 1.13.2	   | [MIT](https://github.com/jquery/jquery-ui/blob/1.13.2/LICENSE.txt) |                     |
| [TableCSVExport](https://github.com/ZachWick/TableCSVExport)  | head	     | MIT  |
| [Tablesorter](https://github.com/Mottie/tablesorter)          | 2.31.1	   | Dual licensed under MIT or GPL licenses                            |
| [W3 CSS](https://www.w3schools.com/w3css/w3css_downloads.asp) | 4.15	     | Public domain                                                      |

Note: For items where no license link is provided, the license statement is only included in file header comments and not as a separate file in the repository.

# libwifi
802.11 Parsing / Generation library

| Build Status                                                                       | OS    | Architecture |
| ---------------------------------------------------------------------------------- | ------| ------------ |
|![X86_64](https://github.com/libwifi/libwifi/actions/workflows/x86_64.yml/badge.svg) | Linux | x86_64       |

## What is this?
libwifi is a C library with a permissive license for generating and parsing a wide variety of 802.11 wireless frames (see the [Feature Checklist](https://libwifi.so/features)) on Linux with a few lines of straight forward code (see the [Examples section](#examples) below).

It is written with a simple-to-use approach while also exposing features that allow more advanced use, with clean and readable code being a priority. Other goals of the library include cross-architecture support, clean compilation without warnings and strict error checking.

The library is fully documented with code comments in both the headers files and the code files.

## Building and Installing
### Building as Release
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```
### Building as Debug
You can also specify `-DCMAKE_BUILD_TYPE=Debug` to CMake, to generate a library with debug symbols present. This also sets the library version number to `dev-BRANCHNAME-COMMITHASH`.
```
$ mkdir build
$ cd build
$ cmake .. -DCMAKE_BUILD_TYPE=Debug
$ make
$ sudo make install
```
```
$ ./test_misc
libwifi version: dev-fixup-7909700
```

## Examples
Some examples are available in the [examples](https://github.com/libwifi/libwifi/tree/main/examples) directory, which show the general flow of how libwifi is used to generate and parse different types of 802.11 frame.

## Running Tests
Using ctest, you can run the tests for the parse and generation functions of libwifi.
```
$ cd test/
$ mkdir build
$ cd build
$ cmake ..
$ make && make test
```

## Using Utilities
Included in the source are some utilities that use libwifi, and serve as references or examples if you need them.
```
$ cd utils/
$ mkdir build
$ cd build
$ cmake ..
$ make
```


# libwifi
802.11 Parsing / Generation library

| Build Status                                                                       | OS    | Architecture |
| ---------------------------------------------------------------------------------- | ------| ------------ |
|![X86_64](https://github.com/libwifi/libwifi/actions/workflows/x86_64.yml/badge.svg) | Linux | x86_64       |

## What is this?
libwifi is a C library with a permissive license for generating and parsing a wide variety of 802.11 wireless frames (see the [Feature Checklist](https://libwifi.so/features) below) on Linux with a few lines of straight forward code (see the [Examples section](#examples) below).

It is written with a simple-to-use approach while also exposing features that allow more advanced use, with clean and readable code being a priority. Other goals of the library include cross-architecture support, clean compilation without warnings and strict error checking.

The library is fully documented with code comments in both the headers files and the code files, and also has doxygen HTML documentation in `docs/html`.

## Building and Installing
### Linux
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

## Examples
Some examples are available in the `examples/` directory, which show the general flow of how libwifi is used to generate and parse different types of 802.11 frame.

## Running Tests
```
$ cd tests/
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo iw <interface> set type monitor && sudo ip link set dev <interface> up
$ ./test-program
```



# spalloc

Toy allocator written in Zig, inspired by [Sys.Pro](https://sys.pro/) C programming language course task.

## Features
- No chunk headers
- Using additional memory only when chunks get allocated
- Special treatment of different types of chunks for better performance

## Usage
`spalloc.h` provides `spmalloc`, `spcalloc`, `sprealloc` and `spfree` functions. These functions have the same API as the standard C `malloc`, `calloc`, `realloc` and `free`.

## Building
Just use `zig build` with standard optimization options. By default it builds a static library.
To build the shared version, pass `-Dshared` option.

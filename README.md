# spalloc

Toy allocator written in Zig, inspired by Sys.Pro C programming language course task.

## Features
- No headers before chunks
- Using additional memory only when chunks get allocated
- Support for special treatment of different types of chunks:
  - Small - `sz <= 128 B` with every chunk being 16 bytes bigger then the last one
  - Medium - `256 B < sz <= 32 KiB` with every next chunk being twice as large as the previous one
  - Large - `32 KiB < sz` with rounding to the page size

## Usage
`spalloc.h` provides `spmalloc`, `spcalloc`, `sprealloc` and `spfree` functions. These functions have the same API as the standard C `malloc`, `calloc`, `realloc` and `free`.

## Building
Just use `zig build` with standard optimization options. By default it builds a static library.
To build the shared version, pass `-Dshared` option.

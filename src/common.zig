const std = @import("std");

pub const KiB = 1024;
pub const MiB = 1024 * KiB;

pub const consts = struct {
    pub const MIN_CHUNK_SIZE = 16;
    pub const MAX_SMALL_CHUNK_SIZE = 256;
    pub const MIN_MEDIUM_CHUNK_SIZE = MAX_SMALL_CHUNK_SIZE * 2;
    pub const MAX_MEDIUM_CHUNK_SIZE = 32 * KiB;

    pub const CHUNK_SIZE_STEP = 16;
    pub const CHUNK_ALIGNMENT = 8;
};

pub const ErasedPtr = [*]align(consts.CHUNK_ALIGNMENT) u8;
pub const Error = std.mem.Allocator.Error;

pub fn getMemoryPages(n: usize) Error!ErasedPtr {
    return (try std.heap.page_allocator.alignedAlloc(u8, std.mem.page_size, n * std.mem.page_size)).ptr;
}

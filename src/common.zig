const std = @import("std");

pub const KiB = 1024;
pub const MiB = 1024 * KiB;

pub const CHUNK_ALIGNMENT = 8;

pub const ErasedPtr = [*]align(CHUNK_ALIGNMENT) u8;
pub const Chunk = struct { ptr: ErasedPtr, size: usize };
pub const Error = std.mem.Allocator.Error;

pub const OsMemoryAllocator = std.heap.page_allocator;
pub fn allocatePages(allocator: std.mem.Allocator, size: usize) Error!ErasedPtr {
    return (try allocator.alignedAlloc(u8, std.mem.page_size, size)).ptr;
}

pub fn freePages(allocator: std.mem.Allocator, ptr: ErasedPtr, size: usize) void {
    std.debug.assert(std.mem.isAligned(@intFromPtr(ptr), std.mem.page_size));

    allocator.free(ptr[0..size]);
}

pub fn memmove(comptime T: type, dest: []T, src: []const T) void {
    if (@intFromPtr(dest.ptr) <= @intFromPtr(src.ptr)) {
        std.mem.copyForwards(T, dest, src);
    } else {
        std.mem.copyBackwards(T, dest, src);
    }
}

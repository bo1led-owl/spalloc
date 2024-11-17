const std = @import("std");

pub const KiB = 1024;
pub const MiB = 1024 * KiB;

pub const consts = struct {
    pub const CHUNK_SIZE_STEP = 16;
    pub const CHUNK_ALIGNMENT = 8;
};

pub const ErasedPtr = [*]align(consts.CHUNK_ALIGNMENT) u8;
pub const Error = std.mem.Allocator.Error;

pub fn getMemoryPages(n: usize) Error!ErasedPtr {
    return (try std.heap.page_allocator.alignedAlloc(u8, std.mem.page_size, n * std.mem.page_size)).ptr;
}

pub fn memmove(comptime T: type, dest: []T, src: []const T) void {
    if (@intFromPtr(dest.ptr) <= @intFromPtr(src.ptr)) {
        std.mem.copyForwards(T, dest, src);
    } else {
        std.mem.copyBackwards(T, dest, src);
    }
}

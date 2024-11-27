const std = @import("std");
const libc = @cImport({
    @cInclude("stdlib.h");
});

const config = @import("config.zig");
const common = @import("common.zig");
const Error = common.Error;
const ErasedPtr = common.ErasedPtr;

const pools_arena = @import("pools_arena.zig");
const buddy_system_arena = @import("buddy_system_arena.zig");

pub const SpAllocator = struct {
    const Self = @This();

    fn chunkCmp(a: common.Chunk, b: common.Chunk) std.math.Order {
        return std.math.order(@intFromPtr(a.ptr), @intFromPtr(b.ptr));
    }

    const AllocatedChunks = std.Treap(common.Chunk, chunkCmp);
    const AllocatedChunksNodeMemPool = std.heap.MemoryPool(AllocatedChunks.Node);

    const SmallChunksArena = pools_arena.PoolsArena(.{
        .min_chunk_size = config.MIN_SMALL_CHUNK_SIZE,
        .max_chunk_size = config.MAX_SMALL_CHUNK_SIZE,
        .chunk_size_step = config.SMALL_CHUNK_SIZE_STEP,
    });
    const MediumChunksArena = buddy_system_arena.BuddySystemArena(.{
        .min_chunk_size = config.MIN_MEDIUM_CHUNK_SIZE,
        .max_chunk_size = config.MAX_MEDIUM_CHUNK_SIZE,
    });

    backing_allocator: std.mem.Allocator,

    small_chunks_arena: SmallChunksArena,
    medium_chunks_arena: MediumChunksArena,

    allocated_chunks_node_mempool: AllocatedChunksNodeMemPool,
    allocated_chunks: AllocatedChunks,

    pub fn init(backing_allocator: std.mem.Allocator) Self {
        const allocated_chunks_node_mempool = AllocatedChunksNodeMemPool.init(backing_allocator);

        return Self{
            .backing_allocator = backing_allocator,
            .small_chunks_arena = SmallChunksArena.init(backing_allocator),
            .medium_chunks_arena = MediumChunksArena.init(backing_allocator),
            .allocated_chunks_node_mempool = allocated_chunks_node_mempool,
            .allocated_chunks = AllocatedChunks{},
        };
    }

    pub const LeakCheckResult = enum {
        ok,
        leak,
    };
    pub fn detectLeaks(self: Self) LeakCheckResult {
        if (self.allocated_chunks.root != null) {
            return .leak;
        }
        return .ok;
    }

    pub const DeinitOptions = enum {
        silent,
        report_leaks,
    };
    pub fn deinit(self: *Self, options: DeinitOptions) LeakCheckResult {
        const result = self.detectLeaks();
        if (result == .leak and options == DeinitOptions.report_leaks) {
            var iter = self.allocated_chunks.inorderIterator();

            while (iter.next()) |node| {
                std.log.err("Memory leak of address 0x{x} detected", .{@intFromPtr(node.key.ptr)});
            }
        }

        self.small_chunks_arena.deinit();
        self.medium_chunks_arena.deinit();
        self.allocated_chunks_node_mempool.deinit();
        return result;
    }

    fn getChunkSize(self: *Self, ptr: ErasedPtr) ?usize {
        const entry = self.allocated_chunks.getEntryFor(common.Chunk{ .ptr = ptr, .size = undefined });
        if (entry.node) |node| {
            return node.key.size;
        }

        return null;
    }

    fn markChunkAllocated(self: *Self, chunk: common.Chunk) Error!void {
        const allocated_chunk_header = common.Chunk{ .ptr = chunk.ptr, .size = chunk.size };

        const new_node: *AllocatedChunks.Node = try self.allocated_chunks_node_mempool.create();
        new_node.key = allocated_chunk_header;

        var entry = self.allocated_chunks.getEntryFor(allocated_chunk_header);
        std.debug.assert(entry.node == null);

        entry.set(new_node);
    }

    pub fn malloc(self: *Self, requested_size: usize) Error!?ErasedPtr {
        if (requested_size == 0) {
            return null;
        }

        var result: common.Chunk = undefined;

        if (SmallChunksArena.chunkFits(requested_size)) {
            result = try self.small_chunks_arena.getChunk(requested_size);
        } else if (MediumChunksArena.chunkFits(requested_size)) {
            result = try self.medium_chunks_arena.getChunk(requested_size);
        } else {
            const aligned_size_overflows_usize = std.math.maxInt(usize) - requested_size < std.mem.page_size;
            result.size = if (aligned_size_overflows_usize)
                std.math.maxInt(usize)
            else
                std.mem.alignForward(usize, requested_size, std.mem.page_size);
            result.ptr = try common.allocatePages(self.backing_allocator, result.size);
        }

        try self.markChunkAllocated(result);
        return result.ptr;
    }

    pub fn calloc(self: *Self, n: usize, elem_size: usize) Error!?ErasedPtr {
        const ptr = try self.malloc(n * elem_size) orelse return null;
        @memset(ptr[0..(n * elem_size)], 0);
        return ptr;
    }

    pub const FreeError = error{
        InvalidAddress,
    };
    pub fn realloc(self: *Self, ptr: ?*anyopaque, requested_size: usize) !?ErasedPtr {
        if (ptr == null) {
            return self.malloc(requested_size);
        }

        if (!std.mem.isAligned(@intFromPtr(ptr), common.CHUNK_ALIGNMENT)) {
            return FreeError.InvalidAddress;
        }

        const ptr_casted: ErasedPtr = @ptrCast(@alignCast(ptr));
        var chunk_entry = self.allocated_chunks.getEntryFor(common.Chunk{ .ptr = ptr_casted, .size = undefined });
        if (chunk_entry.node == null) {
            // `ptr` was not found in allocated blocks addresses
            return FreeError.InvalidAddress;
        }

        var node = chunk_entry.node.?;
        const cur_size = node.key.size;

        if (cur_size >= requested_size) {
            // no need to resize
            return ptr_casted;
        }

        // specific things when resizing medium arena chunks
        const cur_is_medium = MediumChunksArena.chunkFits(cur_size);
        const requested_is_medium = MediumChunksArena.chunkFits(requested_size);
        if (cur_is_medium and requested_is_medium) {
            if (self.medium_chunks_arena.tryResizeChunk(
                ptr_casted,
                cur_size,
                requested_size,
            )) |result| {
                chunk_entry.set(null);
                node.key = result;

                var entry = self.allocated_chunks.getEntryFor(node.key);
                entry.set(node);
                return result.ptr;
            }
        }

        // nothing to do, have to malloc, memcpy and free
        const result = (try self.malloc(requested_size)).?;
        @memcpy(result[0..cur_size], ptr_casted[0..cur_size]);
        self.free(ptr) catch @panic("`free` in `realloc` broke unexpectedly");

        return result;
    }

    pub fn free(self: *Self, ptr: ?*anyopaque) FreeError!void {
        if (ptr == null) {
            return;
        }

        if (!std.mem.isAligned(@intFromPtr(ptr), common.CHUNK_ALIGNMENT)) {
            // invalid (unaligned) address passed
            return FreeError.InvalidAddress;
        }

        var entry = self.allocated_chunks.getEntryFor(common.Chunk{
            .ptr = @ptrCast(@alignCast(ptr)),
            .size = undefined,
        });
        if (entry.node == null) {
            // address that does not match any of the allocated chunks passed
            return FreeError.InvalidAddress;
        }

        const chunk = entry.node.?.key;
        entry.set(null);

        if (SmallChunksArena.chunkFits(chunk.size)) {
            self.small_chunks_arena.putChunk(chunk);
        } else if (MediumChunksArena.chunkFits(chunk.size)) {
            self.medium_chunks_arena.putChunk(chunk);
        } else {
            common.freePages(self.backing_allocator, chunk.ptr, chunk.size);
        }
    }
};

var allocator: SpAllocator = undefined;
var is_allocator_initialized: bool = false;

export fn deinitAllocator() callconv(.C) void {
    _ = allocator.deinit(SpAllocator.DeinitOptions.report_leaks);
}

fn ensureAllocatorIsInitialized() void {
    if (!is_allocator_initialized) {
        allocator = SpAllocator.init(common.OsMemoryAllocator);
        _ = libc.atexit(deinitAllocator);

        is_allocator_initialized = true;
    }
}

pub export fn spmalloc(size: usize) callconv(.C) ?*anyopaque {
    ensureAllocatorIsInitialized();

    return allocator.malloc(size) catch |err| switch (err) {
        error.OutOfMemory => null,
    };
}

pub export fn spcalloc(n: usize, elem_size: usize) callconv(.C) ?*anyopaque {
    ensureAllocatorIsInitialized();

    return allocator.calloc(n, elem_size) catch |err| switch (err) {
        error.OutOfMemory => null,
    };
}

pub export fn sprealloc(ptr: ?*anyopaque, size: usize) callconv(.C) ?*anyopaque {
    ensureAllocatorIsInitialized();

    return allocator.realloc(@ptrCast(@alignCast(ptr)), size) catch |err| switch (err) {
        error.InvalidAddress => {
            std.log.err("`realloc` of invalid address 0x{x}", .{@intFromPtr(ptr.?)});
            std.process.abort();
        },
        error.OutOfMemory => null,
    };
}

pub export fn spfree(ptr: ?*anyopaque) void {
    ensureAllocatorIsInitialized();

    allocator.free(@ptrCast(ptr)) catch |err| switch (err) {
        error.InvalidAddress => {
            std.log.err("`free` of invalid address 0x{x}", .{@intFromPtr(ptr.?)});
            std.process.abort();
        },
    };
}

test "zero size allocation" {
    allocator = SpAllocator.init(std.testing.allocator);
    defer std.debug.assert(allocator.deinit(SpAllocator.DeinitOptions.silent) == .ok);

    try std.testing.expectEqual(null, try allocator.malloc(0));
}

test "null free" {
    allocator = SpAllocator.init(std.testing.allocator);
    defer std.debug.assert(allocator.deinit(SpAllocator.DeinitOptions.silent) == .ok);

    try std.testing.expect(allocator.free(null) != SpAllocator.FreeError.InvalidAddress);
}

test "basic" {
    allocator = SpAllocator.init(std.testing.allocator);
    defer std.debug.assert(allocator.deinit(SpAllocator.DeinitOptions.silent) == .ok);

    const len = 16;
    var pointers = [_]*u32{undefined} ** len;
    for (0..len) |i| {
        pointers[i] = @ptrCast(try allocator.malloc(@sizeOf(u32)));
        pointers[i].* = @intCast(i);
    }

    for (0..len) |i| {
        try allocator.free(pointers[i]);
    }

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "allocate, deallocate, allocate the same block" {
    allocator = SpAllocator.init(std.testing.allocator);
    defer std.debug.assert(allocator.deinit(SpAllocator.DeinitOptions.silent) == .ok);

    var p = try allocator.malloc(@sizeOf(u32));
    try allocator.free(p);
    p = try allocator.malloc(@sizeOf(u32));
    try allocator.free(p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "medium size chunks" {
    allocator = SpAllocator.init(std.testing.allocator);
    defer std.debug.assert(allocator.deinit(SpAllocator.DeinitOptions.silent) == .ok);

    var p: [*]u8 = (try allocator.malloc(config.MAX_SMALL_CHUNK_SIZE + 15)).?;
    p[config.MAX_SMALL_CHUNK_SIZE + 14] = 42;
    try allocator.free(p);

    p = (try allocator.malloc(config.MIN_MEDIUM_CHUNK_SIZE * 4)).?;
    p[config.MIN_MEDIUM_CHUNK_SIZE * 4 - 3] = 42;
    try allocator.free(p);

    p = (try allocator.malloc(config.MAX_MEDIUM_CHUNK_SIZE)).?;
    p[config.MAX_MEDIUM_CHUNK_SIZE - 3] = 42;
    try allocator.free(p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "large chunks" {
    allocator = SpAllocator.init(std.testing.allocator);
    defer std.debug.assert(allocator.deinit(SpAllocator.DeinitOptions.silent) == .ok);

    var p: [*]u8 = (try allocator.malloc(config.MAX_MEDIUM_CHUNK_SIZE + 15)).?;
    p[config.MAX_MEDIUM_CHUNK_SIZE + 14] = 42;
    try allocator.free(p);

    p = (try allocator.malloc(config.MAX_MEDIUM_CHUNK_SIZE * 2)).?;
    p[config.MAX_MEDIUM_CHUNK_SIZE * 2 - 3] = 42;
    try allocator.free(p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "out of memory" {
    allocator = SpAllocator.init(std.testing.allocator);
    defer std.debug.assert(allocator.deinit(SpAllocator.DeinitOptions.silent) == .ok);

    var size: usize = std.math.maxInt(usize);
    size -= size % config.SMALL_CHUNK_SIZE_STEP;

    const p = allocator.malloc(size);
    try std.testing.expectEqual(Error.OutOfMemory, p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "leak" {
    allocator = SpAllocator.init(std.testing.allocator);
    defer std.debug.assert(allocator.deinit(SpAllocator.DeinitOptions.silent) == .ok);

    const p = (try allocator.malloc(16)).?;
    try std.testing.expectEqual(.leak, allocator.detectLeaks());

    try allocator.free(p);
}

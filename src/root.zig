const std = @import("std");
const libc = @cImport({
    @cInclude("stdlib.h");
});

const common = @import("common.zig");
const Error = common.Error;
const ErasedPtr = common.ErasedPtr;
const consts = common.consts;

const SmallChunkPool = @import("SmallChunkPool.zig");
const MediumChunkArena = @import("MediumChunkArena.zig"); 

const AllocatedChunk = struct {
    payload: ErasedPtr,
    size: usize,

    fn cmp(a: AllocatedChunk, b: AllocatedChunk) std.math.Order {
        return std.math.order(@intFromPtr(a.payload), @intFromPtr(b.payload));
    }
};

pub const SpAllocator = struct {
    const Self = @This();

    const AllocatedChunks = std.Treap(AllocatedChunk, AllocatedChunk.cmp);
    const AllocatedChunksNodeMemPool = std.heap.MemoryPool(AllocatedChunks.Node);

    const SMALL_CHUNK_POOLS_COUNT = consts.MAX_SMALL_CHUNK_SIZE / consts.CHUNK_SIZE_STEP;

    small_chunk_pools_node_mempool: SmallChunkPool.NodeMemPool,
    small_chunk_pools: [SMALL_CHUNK_POOLS_COUNT]SmallChunkPool,

    medium_chunk_arena_node_mempool: MediumChunkArena.NodeMemPool,
    medium_chunk_arena: MediumChunkArena,

    allocated_chunks_node_mempool: AllocatedChunksNodeMemPool,
    allocated_chunks: AllocatedChunks,

    pub fn init() Self {
        var small_chunk_pools: [SMALL_CHUNK_POOLS_COUNT]SmallChunkPool =
            [_]SmallChunkPool{undefined} ** SMALL_CHUNK_POOLS_COUNT;
        for (0..SMALL_CHUNK_POOLS_COUNT) |i| {
            const cur_chunk_size = (i + 1) * consts.CHUNK_SIZE_STEP;
            std.debug.assert(consts.MIN_CHUNK_SIZE <= cur_chunk_size);
            std.debug.assert(cur_chunk_size <= consts.MAX_SMALL_CHUNK_SIZE);
            std.debug.assert(cur_chunk_size % consts.CHUNK_SIZE_STEP == 0);

            small_chunk_pools[i] = SmallChunkPool.init(cur_chunk_size);
        }

        const small_chunk_pools_node_mempool = SmallChunkPool.NodeMemPool.init(std.heap.page_allocator);
        const medium_chunk_arena_node_mempool = MediumChunkArena.NodeMemPool.init(std.heap.page_allocator);
        const allocated_chunks_node_mempool = AllocatedChunksNodeMemPool.init(std.heap.page_allocator);

        return Self{
            .small_chunk_pools_node_mempool = small_chunk_pools_node_mempool,
            .small_chunk_pools = small_chunk_pools,
            .medium_chunk_arena_node_mempool = medium_chunk_arena_node_mempool,
            .medium_chunk_arena = MediumChunkArena{},
            .allocated_chunks_node_mempool = allocated_chunks_node_mempool,
            .allocated_chunks = AllocatedChunks{},
        };
    }

    const LeakCheckResult = enum {
        ok,
        leak,
    };

    pub fn detectLeaks(self: Self) LeakCheckResult {
        if (self.allocated_chunks.root != null) {
            return .leak;
        }
        return .ok;
    }

    pub fn deinit(self: *Self, report_leaks: bool) LeakCheckResult {
        const result = self.detectLeaks();
        if (result == .leak and report_leaks) {
            var iter = self.allocated_chunks.inorderIterator();

            while (iter.next()) |node| {
                std.log.err("Memory leak of address 0x{x} detected", .{@intFromPtr(node.key.payload)});
            }
        }

        for (self.small_chunk_pools[0..SMALL_CHUNK_POOLS_COUNT]) |*pool| {
            pool.deinit();
        }
        self.medium_chunk_arena.deinit();
        self.small_chunk_pools_node_mempool.deinit();
        self.allocated_chunks_node_mempool.deinit();
        return result;
    }

    fn getSmallChunkPoolIndex(size: usize) usize {
        std.debug.assert(consts.MIN_CHUNK_SIZE <= size);
        std.debug.assert(size <= consts.MAX_SMALL_CHUNK_SIZE);
        std.debug.assert(size % consts.CHUNK_SIZE_STEP == 0);

        const result = size / consts.CHUNK_SIZE_STEP - 1;
        std.debug.assert(result < SMALL_CHUNK_POOLS_COUNT);
        return result;
    }

    fn getChunkSize(self: *Self, ptr: ErasedPtr) ?usize {
        const entry = self.allocated_chunks.getEntryFor(AllocatedChunk{ .payload = ptr, .size = undefined });
        if (entry.node) |node| {
            return node.key.size;
        }

        return null;
    }

    fn markChunkAllocated(self: *Self, chunk_ptr: ErasedPtr, chunk_size: usize) Error!void {
        const allocated_chunk_header = AllocatedChunk{ .payload = chunk_ptr, .size = chunk_size };

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

        var size: usize = undefined;
        var ptr: ErasedPtr = undefined;

        size = std.mem.alignForward(usize, requested_size, consts.CHUNK_SIZE_STEP);
        switch (size) {
            0...consts.MAX_SMALL_CHUNK_SIZE => {
                const pool_index = getSmallChunkPoolIndex(size);

                std.debug.assert(self.small_chunk_pools[pool_index].chunk_size == size);

                ptr = try self.small_chunk_pools[pool_index].getChunk(&self.small_chunk_pools_node_mempool);
            },
            (consts.MAX_SMALL_CHUNK_SIZE + 1)...consts.MAX_MEDIUM_CHUNK_SIZE => {
                size = MediumChunkArena.roundSize(requested_size);
                ptr = try self.medium_chunk_arena.getChunk(&self.medium_chunk_arena_node_mempool, size);
            },
            else => {
                if (std.math.maxInt(usize) - requested_size < std.mem.page_size) {
                    size = std.math.maxInt(usize);
                } else {
                    size = std.mem.alignForward(usize, requested_size, std.mem.page_size);
                }
                ptr = (try std.heap.page_allocator.alignedAlloc(u8, std.mem.page_size, size)).ptr;
            },
        }

        try self.markChunkAllocated(ptr, size);

        return ptr;
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

        if (!std.mem.isAligned(@intFromPtr(ptr), consts.CHUNK_ALIGNMENT)) {
            return FreeError.InvalidAddress;
        }

        const ptr_casted: ErasedPtr = @ptrCast(@alignCast(ptr));
        var chunk_entry = self.allocated_chunks.getEntryFor(AllocatedChunk{ .payload = ptr_casted, .size = undefined });
        if (chunk_entry.node == null) {
            return FreeError.InvalidAddress;
        }

        var node = chunk_entry.node.?;
        const cur_size = node.key.size;

        if (cur_size >= requested_size) {
            return ptr_casted;
        }

        if (consts.MAX_SMALL_CHUNK_SIZE < cur_size and cur_size <= consts.MAX_MEDIUM_CHUNK_SIZE and
            consts.MAX_SMALL_CHUNK_SIZE < requested_size and requested_size <= consts.MAX_MEDIUM_CHUNK_SIZE)
        {
            const new_size = MediumChunkArena.roundSize(requested_size);

            const result = self.medium_chunk_arena.tryResizeChunk(ptr_casted, cur_size, new_size);
            if (result) |res_ptr| {
                chunk_entry.set(null);
                node.key = AllocatedChunk{ .payload = res_ptr, .size = new_size };

                var entry = self.allocated_chunks.getEntryFor(node.key);
                entry.set(node);

                return res_ptr;
            }
        }

        const result = (try self.malloc(requested_size)).?;
        @memcpy(result[0..cur_size], ptr_casted[0..cur_size]);
        self.free(ptr) catch @panic("`free` in `realloc` broke unexpectedly");

        return result;
    }

    pub fn free(self: *Self, ptr: ?*anyopaque) FreeError!void {
        if (ptr == null) {
            return;
        }

        if (!std.mem.isAligned(@intFromPtr(ptr), consts.CHUNK_ALIGNMENT)) {
            return FreeError.InvalidAddress;
        }

        var entry = self.allocated_chunks.getEntryFor(AllocatedChunk{
            .payload = @ptrCast(@alignCast(ptr)),
            .size = undefined,
        });
        if (entry.node == null) {
            return FreeError.InvalidAddress;
        }

        const chunk = entry.node.?.key;
        entry.set(null);

        if (chunk.size <= consts.MAX_SMALL_CHUNK_SIZE) {
            const pool_index = getSmallChunkPoolIndex(chunk.size);
            self.small_chunk_pools[pool_index].putChunk(chunk.payload);
        } else if (chunk.size <= consts.MAX_MEDIUM_CHUNK_SIZE) {
            self.medium_chunk_arena.putChunk(chunk.payload, chunk.size);
        } else {
            std.heap.page_allocator.free(chunk.payload[0..chunk.size]);
        }
    }
};

var allocator: SpAllocator = undefined;
var is_allocator_initialized: bool = false;

export fn deinitAllocator() callconv(.C) void {
    _ = allocator.deinit(true);
}

fn ensureAllocatorIsInitialized() void {
    if (!is_allocator_initialized) {
        allocator = SpAllocator.init();
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

test "round size" {
    try std.testing.expectEqual(256, MediumChunkArena.roundSize(142));
    try std.testing.expectEqual(256, MediumChunkArena.roundSize(256));
    try std.testing.expectEqual(512, MediumChunkArena.roundSize(257));
}

test "zero size allocation" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    try std.testing.expectEqual(null, try allocator.malloc(0));
}

test "null free" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    try std.testing.expect(allocator.free(null) != SpAllocator.FreeError.InvalidAddress);
}

test "basic" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

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
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    var p = try allocator.malloc(@sizeOf(u32));
    try allocator.free(p);
    p = try allocator.malloc(@sizeOf(u32));
    try allocator.free(p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "medium size chunks" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    var p: [*]u8 = (try allocator.malloc(consts.MAX_SMALL_CHUNK_SIZE + 15)).?;
    p[consts.MAX_SMALL_CHUNK_SIZE + 14] = 42;
    try allocator.free(p);

    p = (try allocator.malloc(consts.MIN_MEDIUM_CHUNK_SIZE * 4)).?;
    p[consts.MIN_MEDIUM_CHUNK_SIZE * 4 - 3] = 42;
    try allocator.free(p);

    p = (try allocator.malloc(consts.MAX_MEDIUM_CHUNK_SIZE)).?;
    p[consts.MAX_MEDIUM_CHUNK_SIZE - 3] = 42;
    try allocator.free(p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "large chunks" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    var p: [*]u8 = (try allocator.malloc(consts.MAX_MEDIUM_CHUNK_SIZE + 15)).?;
    p[consts.MAX_MEDIUM_CHUNK_SIZE + 14] = 42;
    try allocator.free(p);

    p = (try allocator.malloc(consts.MAX_MEDIUM_CHUNK_SIZE * 2)).?;
    p[consts.MAX_MEDIUM_CHUNK_SIZE * 2 - 3] = 42;
    try allocator.free(p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "out of memory" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    var size: usize = std.math.maxInt(usize);
    size -= size % consts.CHUNK_SIZE_STEP;

    const p = allocator.malloc(size);
    try std.testing.expectEqual(Error.OutOfMemory, p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "leak" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    const p = (try allocator.malloc(16)).?;
    try std.testing.expectEqual(.leak, allocator.detectLeaks());

    try allocator.free(p);
}

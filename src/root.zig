const std = @import("std");
const libc = @cImport(@cInclude("stdlib.h"));

const Error = std.mem.Allocator.Error;

const KiB = 1024;
const MiB = 1024 * KiB;

const MIN_CHUNK_SIZE = 16;
const MAX_SMALL_CHUNK_SIZE = 128;
const MIN_MEDIUM_CHUNK_SIZE = MAX_SMALL_CHUNK_SIZE * 2;
const MAX_MEDIUM_CHUNK_SIZE = 8 * KiB;

const CHUNK_SIZE_STEP = 16;
const CHUNK_ALIGNMENT = 8;

const FreeChunk = struct {
    next: ?*FreeChunk,
};

comptime {
    std.debug.assert(@sizeOf(FreeChunk) <= MIN_CHUNK_SIZE);
    std.debug.assert(@alignOf(FreeChunk) == CHUNK_ALIGNMENT);
}

const ErasedPtr = [*]align(CHUNK_ALIGNMENT) u8;

fn getMemoryPages(n: usize) Error!ErasedPtr {
    return (try std.heap.page_allocator.alignedAlloc(u8, std.mem.page_size, n * std.mem.page_size)).ptr;
}

const SmallChunkPool = struct {
    const NodeMemPool = std.heap.MemoryPool(Buffers.Node);

    const Buffer = struct {
        const SIZE = std.mem.page_size;

        ptr: ErasedPtr,

        pub fn init() Error!Buffer {
            return Buffer{
                .ptr = try getMemoryPages(SIZE / std.mem.page_size),
            };
        }

        pub fn getChunksCount(chunk_size: usize) usize {
            std.debug.assert(chunk_size % CHUNK_SIZE_STEP == 0);

            return std.mem.page_size / chunk_size;
        }

        pub fn getNthChunk(self: Buffer, chunk_size: usize, n: usize) *FreeChunk {
            std.debug.assert(chunk_size % CHUNK_SIZE_STEP == 0);
            std.debug.assert(chunk_size * n < std.mem.page_size);

            return @ptrCast(@alignCast(self.ptr + (chunk_size * n)));
        }
    };

    const Buffers = std.SinglyLinkedList(Buffer);

    chunk_size: usize,
    buffers: Buffers,
    first_free_chunk: ?*FreeChunk,

    pub fn init(chunk_size: usize) SmallChunkPool {
        return .{
            .buffers = .{},
            .chunk_size = chunk_size,
            .first_free_chunk = null,
        };
    }

    pub fn deinit(self: *SmallChunkPool) void {
        var cur_node = self.buffers.first;
        while (cur_node) |node| : (cur_node = cur_node.?.next) {
            std.heap.page_allocator.free(node.data.ptr[0..Buffer.SIZE]);
        }
    }

    fn addNewBuffer(self: *SmallChunkPool, node_mempool: *NodeMemPool) Error!void {
        const new_node: *Buffers.Node = try node_mempool.create();
        const new_chunk = try Buffer.init();
        new_node.data = new_chunk;
        self.buffers.prepend(new_node);

        for (0..Buffer.getChunksCount(self.chunk_size) - 1) |i| {
            var cur_chunk = new_chunk.getNthChunk(self.chunk_size, i);
            cur_chunk.next = new_chunk.getNthChunk(self.chunk_size, i + 1);
        }
        new_chunk.getNthChunk(self.chunk_size, Buffer.getChunksCount(self.chunk_size) - 1).next = null;

        self.first_free_chunk = new_chunk.getNthChunk(self.chunk_size, 0);
    }

    pub fn putChunk(self: *SmallChunkPool, ptr: ErasedPtr) void {
        const new_chunk: *FreeChunk = @ptrCast(ptr);
        new_chunk.next = self.first_free_chunk;
        self.first_free_chunk = new_chunk;
    }

    pub fn getChunk(self: *SmallChunkPool, node_mempool: *NodeMemPool) Error!ErasedPtr {
        if (self.first_free_chunk == null) {
            try self.addNewBuffer(node_mempool);
        }

        const result = self.first_free_chunk.?;
        self.first_free_chunk = result.next;
        return @ptrCast(result);
    }
};

const MediumChunkArena = struct {
    const Buffer = struct {
        const SIZE = MAX_MEDIUM_CHUNK_SIZE;

        header: Header,
        ptr: ErasedPtr,

        pub const Header = struct {
            const ReprType = u63;
            const IndexType = u6;

            repr: ReprType,

            fn chunkHasChildren(index: IndexType) bool {
                return (index + 1) < 32;
            }

            fn getChildrenMask(index: IndexType) ReprType {
                if (!chunkHasChildren(index)) {
                    return 0;
                }

                const l_child = 2 * (index + 1) - 1;
                const r_child = 2 * (index + 1) + 1 - 1;
                return (@as(ReprType, @intCast(1)) << l_child) |
                    (@as(ReprType, @intCast(1)) << r_child) |
                    getChildrenMask(l_child) |
                    getChildrenMask(r_child);
            }

            fn getParentMask(index: IndexType) ReprType {
                var result: ReprType = 0;

                var i = (index + 1) / 2;
                while (i > 0) : (i /= 2) {
                    result |= @as(ReprType, @intCast(1)) << (i - 1);
                }

                return result;
            }

            pub fn isChunkFree(self: Header, index: IndexType) bool {
                return ((self.repr & (@as(ReprType, @intCast(1)) << index)) |
                    (self.repr & getChildrenMask(index)) |
                    (self.repr & getParentMask(index))) == 0;
            }

            pub fn markChunkFree(self: *Header, index: IndexType) void {
                self.repr &= ~(@as(ReprType, @intCast(1)) << index);
            }

            pub fn markChunkAllocated(self: *Header, index: IndexType) void {
                self.repr |= @as(ReprType, @intCast(1)) << index;
            }
        };

        pub fn init() Error!Buffer {
            return Buffer{
                .header = .{ .repr = 0 },
                .ptr = try getMemoryPages(SIZE / std.mem.page_size),
            };
        }

        pub fn getChunk(self: *Buffer, size: usize) ?ErasedPtr {
            std.debug.assert(size >= MIN_MEDIUM_CHUNK_SIZE);
            std.debug.assert(size <= MAX_MEDIUM_CHUNK_SIZE);
            std.debug.assert(@popCount(size) == 1);

            const chunks_to_check = Buffer.SIZE / size;
            const starting_index = chunks_to_check - 1;

            for (starting_index..(starting_index + chunks_to_check)) |i| {
                if (self.header.isChunkFree(@intCast(i))) {
                    self.header.markChunkAllocated(@intCast(i));

                    const result: ErasedPtr = @alignCast(self.ptr + size * (i - starting_index));
                    std.debug.assert(self.ownsChunk(result));
                    return result;
                }
            }

            return null;
        }

        pub fn putChunk(self: *Buffer, ptr: ErasedPtr, size: usize) void {
            std.debug.assert(self.ownsChunk(ptr));
            std.debug.assert(size >= MIN_MEDIUM_CHUNK_SIZE);
            std.debug.assert(size <= MAX_MEDIUM_CHUNK_SIZE);
            std.debug.assert(@popCount(size) == 1);

            const index: u6 = @intCast((@intFromPtr(ptr) - @intFromPtr(self.ptr)) / size);
            self.header.markChunkFree(index);
        }

        pub fn ownsChunk(self: Buffer, ptr: ErasedPtr) bool {
            return @intFromPtr(ptr) >= @intFromPtr(self.ptr) and
                @intFromPtr(ptr) - @intFromPtr(self.ptr) <= Buffer.SIZE;
        }
    };

    const Buffers = std.SinglyLinkedList(Buffer);
    const NodeMemPool = std.heap.MemoryPool(Buffers.Node);

    chunks: Buffers = .{},

    pub fn deinit(self: *MediumChunkArena) void {
        var cur_node = self.chunks.first;
        while (cur_node) |node| : (cur_node = cur_node.?.next) {
            std.heap.page_allocator.free(node.data.ptr[0..Buffer.SIZE]);
        }
    }

    pub fn putChunk(self: *MediumChunkArena, ptr: ErasedPtr, size: usize) void {
        var cur_node = self.chunks.first;
        while (cur_node) |node| {
            if (node.data.ownsChunk(ptr)) {
                node.data.putChunk(ptr, size);
                return;
            }

            cur_node = node.next;
        }

        unreachable;
    }

    pub fn roundSize(size: usize) usize {
        const shift = std.math.log2_int_ceil(usize, size);
        return std.math.shl(usize, @as(usize, @intCast(1)), shift);
    }

    pub fn getChunk(self: *MediumChunkArena, node_mempool: *NodeMemPool, requested_size: usize) Error!ErasedPtr {
        const size = roundSize(requested_size);

        var cur_node = self.chunks.first;
        while (cur_node) |node| {
            if (node.data.getChunk(size)) |ptr| {
                return ptr;
            }
            cur_node = node.next;
        }

        // didn't find any chunks, have to add new chunk
        cur_node = try node_mempool.create();
        cur_node.?.data = try Buffer.init();
        self.chunks.prepend(cur_node.?);

        return cur_node.?.data.getChunk(size).?;
    }
};

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

    const SMALL_CHUNK_POOLS_COUNT = MAX_SMALL_CHUNK_SIZE / CHUNK_SIZE_STEP;

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
            const cur_chunk_size = (i + 1) * CHUNK_SIZE_STEP;
            std.debug.assert(MIN_CHUNK_SIZE <= cur_chunk_size);
            std.debug.assert(cur_chunk_size <= MAX_SMALL_CHUNK_SIZE);
            std.debug.assert(cur_chunk_size % CHUNK_SIZE_STEP == 0);

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
        std.debug.assert(MIN_CHUNK_SIZE <= size);
        std.debug.assert(size <= MAX_SMALL_CHUNK_SIZE);
        std.debug.assert(size % CHUNK_SIZE_STEP == 0);

        const result = size / CHUNK_SIZE_STEP - 1;
        std.debug.assert(result < SMALL_CHUNK_POOLS_COUNT);
        return result;
    }

    fn getchunkSize(self: *Self, ptr: ErasedPtr) ?usize {
        const entry = self.allocated_chunks.getEntryFor(AllocatedChunk{ .payload = ptr, .size = undefined });
        if (entry.node) |node| {
            return node.key.size;
        }

        return null;
    }

    fn markchunkAllocated(self: *Self, chunk_ptr: ErasedPtr, chunk_size: usize) Error!void {
        const allocated_chunk_header = AllocatedChunk{ .payload = chunk_ptr, .size = chunk_size };

        const new_node: *AllocatedChunks.Node = try self.allocated_chunks_node_mempool.create();
        new_node.key = allocated_chunk_header;

        var entry = self.allocated_chunks.getEntryFor(allocated_chunk_header);
        std.debug.assert(entry.node == null);

        entry.set(new_node);
    }

    pub fn malloc(self: *Self, requested_size: usize) Error!ErasedPtr {
        var size: usize = undefined;
        var ptr: ErasedPtr = undefined;

        size = std.mem.alignForward(usize, requested_size, CHUNK_SIZE_STEP);
        switch (size) {
            0...MAX_SMALL_CHUNK_SIZE => {
                const pool_index = getSmallChunkPoolIndex(size);

                std.debug.assert(self.small_chunk_pools[pool_index].chunk_size == size);

                ptr = try self.small_chunk_pools[pool_index].getChunk(&self.small_chunk_pools_node_mempool);
            },
            (MAX_SMALL_CHUNK_SIZE + 1)...MAX_MEDIUM_CHUNK_SIZE => {
                size = MediumChunkArena.roundSize(requested_size);
                ptr = try self.medium_chunk_arena.getChunk(&self.medium_chunk_arena_node_mempool, size);
            },
            else => {
                size = std.mem.alignForward(usize, requested_size, std.mem.page_size);
                ptr = (try std.heap.page_allocator.alignedAlloc(u8, std.mem.page_size, size)).ptr;
            },
        }

        try self.markchunkAllocated(ptr, size);

        return ptr;
    }

    pub fn calloc(self: *Self, n: usize, elem_size: usize) Error!ErasedPtr {
        const ptr = try self.malloc(n * elem_size);
        @memset(ptr[0..(n * elem_size)], 0);
        return ptr;
    }

    pub const FreeError = error{
        InvalidAddress,
    };
    pub fn realloc(self: *Self, ptr: *anyopaque, size: usize) !ErasedPtr {
        if (!std.mem.isAligned(@intFromPtr(ptr), CHUNK_ALIGNMENT)) {
            return FreeError.InvalidAddress;
        }

        const ptr_casted: ErasedPtr = @ptrCast(@alignCast(ptr));
        const chunk_size = self.getchunkSize(ptr_casted);
        if (chunk_size == null) {
            return FreeError.InvalidAddress;
        } else if (chunk_size.? >= size) {
            return ptr_casted;
        }

        const new_data = try self.malloc(size);
        @memcpy(new_data[0..chunk_size.?], ptr_casted[0..chunk_size.?]);
        self.free(ptr) catch @panic("`free` in `realloc` breaked unexpectedly");

        return new_data;
    }

    pub fn free(self: *Self, ptr: *anyopaque) FreeError!void {
        if (!std.mem.isAligned(@intFromPtr(ptr), CHUNK_ALIGNMENT)) {
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

        if (chunk.size <= MAX_SMALL_CHUNK_SIZE) {
            const pool_index = getSmallChunkPoolIndex(chunk.size);
            self.small_chunk_pools[pool_index].putChunk(chunk.payload);
        } else if (chunk.size <= MAX_MEDIUM_CHUNK_SIZE) {
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
    if (ptr == null) {
        return null;
    }

    ensureAllocatorIsInitialized();

    return allocator.realloc(@ptrCast(@alignCast(ptr.?)), size) catch |err| switch (err) {
        error.InvalidAddress => {
            std.log.err("`realloc` of invalid address 0x{x}", .{@intFromPtr(ptr.?)});
            std.process.abort();
        },
        error.OutOfMemory => null,
    };
}

pub export fn spfree(ptr: ?*anyopaque) void {
    if (ptr == null) {
        return;
    }

    ensureAllocatorIsInitialized();

    allocator.free(@ptrCast(ptr.?)) catch |err| switch (err) {
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

test "medium size chunks" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    var p: [*]u8 = try allocator.malloc(MAX_SMALL_CHUNK_SIZE + 15);
    p[MAX_SMALL_CHUNK_SIZE + 14] = 42;
    try allocator.free(p);

    p = try allocator.malloc(MIN_MEDIUM_CHUNK_SIZE * 4);
    p[MIN_MEDIUM_CHUNK_SIZE * 4 - 3] = 42;
    try allocator.free(p);

    p = try allocator.malloc(MAX_MEDIUM_CHUNK_SIZE);
    p[MAX_MEDIUM_CHUNK_SIZE - 3] = 42;
    try allocator.free(p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "large chunks" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    var p: [*]u8 = try allocator.malloc(MAX_MEDIUM_CHUNK_SIZE + 15);
    p[MAX_MEDIUM_CHUNK_SIZE + 14] = 42;
    try allocator.free(p);

    p = try allocator.malloc(MAX_MEDIUM_CHUNK_SIZE * 2);
    p[MAX_MEDIUM_CHUNK_SIZE * 2 - 3] = 42;
    try allocator.free(p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "leak" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    const p = try allocator.malloc(16);
    try std.testing.expectEqual(.leak, allocator.detectLeaks());

    try allocator.free(p);
}

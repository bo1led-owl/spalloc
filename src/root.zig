const std = @import("std");
const libc = @cImport(@cInclude("stdlib.h"));

const Error = std.mem.Allocator.Error;

const KiB = 1024;
const MiB = 1024 * KiB;

const MIN_BLOCK_SIZE = 16;
const MAX_SMALL_BLOCK_SIZE = 128;
const MIN_MEDIUM_BLOCK_SIZE = MAX_SMALL_BLOCK_SIZE * 2;
const MAX_MEDIUM_BLOCK_SIZE = 8 * KiB;

const BLOCK_SIZE_STEP = 16;
const BLOCK_ALIGNMENT = 8;

const FreeBlock = struct {
    next: ?*FreeBlock,
};

comptime {
    std.debug.assert(@sizeOf(FreeBlock) <= MIN_BLOCK_SIZE);
    std.debug.assert(@alignOf(FreeBlock) == BLOCK_ALIGNMENT);
}

const ErasedPtr = [*]align(BLOCK_ALIGNMENT) u8;

fn getMemoryPages(n: usize) Error!ErasedPtr {
    return (try std.heap.page_allocator.alignedAlloc(u8, std.mem.page_size, n * std.mem.page_size)).ptr;
}

const SmallBlockArena = struct {
    const NodeMemPool = std.heap.MemoryPool(Pages.Node);

    const Page = struct {
        const SIZE = std.mem.page_size;

        ptr: ErasedPtr,

        pub fn init() Error!Page {
            return Page{
                .ptr = try getMemoryPages(SIZE / std.mem.page_size),
            };
        }

        pub fn getBlocksCount(block_size: usize) usize {
            std.debug.assert(block_size % BLOCK_SIZE_STEP == 0);

            return std.mem.page_size / block_size;
        }

        pub fn getNthBlock(self: Page, block_size: usize, n: usize) *FreeBlock {
            std.debug.assert(block_size % BLOCK_SIZE_STEP == 0);
            std.debug.assert(block_size * n < std.mem.page_size);

            return @ptrCast(@alignCast(self.ptr + (block_size * n)));
        }
    };

    const Pages = std.SinglyLinkedList(Page);

    block_size: usize,
    chunks: Pages,
    first_free_block: ?*FreeBlock,

    pub fn init(block_size: usize) SmallBlockArena {
        return SmallBlockArena{
            .chunks = .{},
            .block_size = block_size,
            .first_free_block = null,
        };
    }

    fn addNewChunk(self: *SmallBlockArena, node_mempool: *NodeMemPool) Error!void {
        const new_node: *Pages.Node = try node_mempool.create();
        const new_chunk = try Page.init();
        new_node.data = new_chunk;
        self.chunks.prepend(new_node);

        for (0..Page.getBlocksCount(self.block_size) - 1) |i| {
            var cur_block = new_chunk.getNthBlock(self.block_size, i);
            cur_block.next = new_chunk.getNthBlock(self.block_size, i + 1);
        }
        new_chunk.getNthBlock(self.block_size, Page.getBlocksCount(self.block_size) - 1).next = null;

        self.first_free_block = @ptrCast(@alignCast(new_chunk.ptr));
    }

    pub fn returnBlock(self: *SmallBlockArena, ptr: ErasedPtr) void {
        const new_block: *FreeBlock = @ptrCast(ptr);
        new_block.next = self.first_free_block;
        self.first_free_block = new_block;
    }

    pub fn getBlock(self: *SmallBlockArena, node_mempool: *NodeMemPool) Error!ErasedPtr {
        if (self.first_free_block == null) {
            try self.addNewChunk(node_mempool);
        }

        defer self.first_free_block = self.first_free_block.?.next;
        return @ptrCast(self.first_free_block.?);
    }
};

const MediumBlockArena = struct {
    const Chunk = struct {
        const SIZE = MAX_MEDIUM_BLOCK_SIZE;

        pub const Header = struct {
            const ReprType = u63;
            const IndexType = u6;

            repr: ReprType,

            fn blockHasChildren(index: IndexType) bool {
                return (index + 1) < 32;
            }

            fn getChildrenMask(index: IndexType) ReprType {
                if (!blockHasChildren(index)) {
                    return 0;
                }

                const l_child = 2 * (index + 1) - 1;
                const r_child = 2 * (index + 1);
                return (@as(ReprType, @intCast(1)) << l_child) | (@as(ReprType, @intCast(1)) << r_child) | getChildrenMask(l_child) | getChildrenMask(r_child);
            }

            fn getParentMask(index: IndexType) ReprType {
                var result: ReprType = 0;

                var i = (index + 1) / 2;
                while (i > 0) : (i /= 2) {
                    result |= @as(ReprType, @intCast(1)) << (i - 1);
                }

                return result;
            }

            pub fn isBlockFree(self: Header, index: IndexType) bool {
                return ((self.repr & (@as(ReprType, @intCast(1)) << index)) |
                    (self.repr & getChildrenMask(index)) |
                    (self.repr & getParentMask(index))) == 0;
            }

            pub fn markBlockFree(self: *Header, index: IndexType) void {
                self.repr &= ~(@as(ReprType, @intCast(1)) << index);
            }

            pub fn markBlockAllocated(self: *Header, index: IndexType) void {
                self.repr |= @as(ReprType, @intCast(1)) << index;
            }
        };

        header: Header,
        ptr: ErasedPtr,

        pub fn init() Error!Chunk {
            return Chunk{
                .header = .{ .repr = 0 },
                .ptr = try getMemoryPages(SIZE / std.mem.page_size),
            };
        }

        pub fn getBlock(self: *Chunk, size: usize) ?ErasedPtr {
            std.debug.assert(size >= MIN_MEDIUM_BLOCK_SIZE);
            std.debug.assert(size <= MAX_MEDIUM_BLOCK_SIZE);
            std.debug.assert(@popCount(size) == 1);

            const blocks_to_check = Chunk.SIZE / size;
            const starting_index = blocks_to_check - 1;

            for (starting_index..(starting_index + blocks_to_check)) |i| {
                if (self.header.isBlockFree(@intCast(i))) {
                    self.header.markBlockAllocated(@intCast(i));
                    return @alignCast(self.ptr + size * i);
                }
            }

            return null;
        }

        pub fn returnBlock(self: *Chunk, ptr: ErasedPtr, size: usize) void {
            std.debug.assert(self.ownsBlock(ptr));
            std.debug.assert(size >= MIN_MEDIUM_BLOCK_SIZE);
            std.debug.assert(size <= MAX_MEDIUM_BLOCK_SIZE);
            std.debug.assert(@popCount(size) == 1);

            const index: u6 = @intCast((@intFromPtr(ptr) - @intFromPtr(self.ptr)) / size);
            self.header.markBlockFree(index);
        }

        pub fn ownsBlock(self: Chunk, ptr: ErasedPtr) bool {
            return @intFromPtr(ptr) >= @intFromPtr(self.ptr) and
                @intFromPtr(ptr) - @intFromPtr(self.ptr) <= Chunk.SIZE;
        }
    };

    const Chunks = std.SinglyLinkedList(Chunk);
    const NodeMemPool = std.heap.MemoryPool(Chunks.Node);

    chunks: Chunks = .{},

    pub fn returnBlock(self: *MediumBlockArena, ptr: ErasedPtr, size: usize) void {
        var cur_node = self.chunks.first;
        while (cur_node) |node| {
            if (node.data.ownsBlock(ptr)) {
                node.data.returnBlock(ptr, size);
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

    pub fn getBlock(self: *MediumBlockArena, node_mempool: *NodeMemPool, requested_size: usize) Error!ErasedPtr {
        const size = roundSize(requested_size);

        var cur_node = self.chunks.first;
        while (cur_node) |node| {
            if (node.data.getBlock(size)) |ptr| {
                return ptr;
            }
            cur_node = node.next;
        }

        // didn't find any blocks, have to add new chunk
        const new_node: *Chunks.Node = try node_mempool.create();
        new_node.data = try Chunk.init();
        self.chunks.prepend(new_node);

        return self.chunks.first.?.data.getBlock(size) orelse Error.OutOfMemory;
    }
};

const AllocatedBlock = struct {
    payload: ErasedPtr,
    size: usize,

    fn cmp(a: AllocatedBlock, b: AllocatedBlock) std.math.Order {
        return std.math.order(@intFromPtr(a.payload), @intFromPtr(b.payload));
    }
};

pub const SpAllocator = struct {
    const Self = @This();

    const AllocatedBlocks = std.Treap(AllocatedBlock, AllocatedBlock.cmp);
    const AllocatedBlocksNodeMemPool = std.heap.MemoryPool(AllocatedBlocks.Node);

    const SMALL_BLOCK_ARENAS_COUNT = MAX_SMALL_BLOCK_SIZE / (2 * MIN_BLOCK_SIZE);

    small_arena_node_mempool: SmallBlockArena.NodeMemPool,
    small_arenas: [SMALL_BLOCK_ARENAS_COUNT]SmallBlockArena,

    medium_arena_node_mempool: MediumBlockArena.NodeMemPool,
    medium_arena: MediumBlockArena,

    allocated_blocks_node_mempool: AllocatedBlocksNodeMemPool,
    allocated_blocks: AllocatedBlocks,

    pub fn init() Self {
        const small_arena_node_mempool = SmallBlockArena.NodeMemPool.init(std.heap.page_allocator);
        var small_block_arenas = [_]SmallBlockArena{undefined} ** SMALL_BLOCK_ARENAS_COUNT;
        for (0..SMALL_BLOCK_ARENAS_COUNT) |i| {
            const cur_block_size = (i + 1) * BLOCK_SIZE_STEP;
            std.debug.assert(MIN_BLOCK_SIZE <= cur_block_size);
            std.debug.assert(cur_block_size <= MAX_SMALL_BLOCK_SIZE);
            std.debug.assert(cur_block_size % BLOCK_SIZE_STEP == 0);

            small_block_arenas[i] = SmallBlockArena.init(cur_block_size);
        }

        const medium_arena_node_mempool = MediumBlockArena.NodeMemPool.init(std.heap.page_allocator);

        const allocated_blocks_node_mempool = AllocatedBlocksNodeMemPool.init(std.heap.page_allocator);

        return Self{
            .small_arena_node_mempool = small_arena_node_mempool,
            .small_arenas = small_block_arenas,
            .medium_arena_node_mempool = medium_arena_node_mempool,
            .medium_arena = MediumBlockArena{},
            .allocated_blocks_node_mempool = allocated_blocks_node_mempool,
            .allocated_blocks = AllocatedBlocks{},
        };
    }

    const LeakCheckResult = enum {
        ok,
        leak,
    };

    pub fn detectLeaks(self: Self) LeakCheckResult {
        if (self.allocated_blocks.root != null) {
            return .leak;
        }
        return .ok;
    }

    pub fn deinit(self: *Self, report_leaks: bool) LeakCheckResult {
        const result = self.detectLeaks();
        if (result == .leak and report_leaks) {
            var iter = self.allocated_blocks.inorderIterator();

            while (iter.next()) |node| {
                std.log.err("Memory leak of address 0x{x} detected", .{@intFromPtr(node.key.payload)});
            }
        }

        self.small_arena_node_mempool.deinit();
        self.allocated_blocks_node_mempool.deinit();
        return result;
    }

    fn getSmallBlockArenaIndex(size: usize) usize {
        std.debug.assert(MIN_BLOCK_SIZE <= size);
        std.debug.assert(size <= MAX_SMALL_BLOCK_SIZE);
        std.debug.assert(size % BLOCK_SIZE_STEP == 0);
        return size / BLOCK_SIZE_STEP - 1;
    }

    fn getBlockSize(self: *Self, ptr: ErasedPtr) ?usize {
        const entry = self.allocated_blocks.getEntryFor(AllocatedBlock{ .payload = ptr, .size = undefined });
        if (entry.node) |node| {
            return node.key.size;
        }

        return null;
    }

    fn markBlockAllocated(self: *Self, block_ptr: ErasedPtr, block_size: usize) Error!void {
        const allocated_block_header = AllocatedBlock{ .payload = block_ptr, .size = block_size };

        var entry = self.allocated_blocks.getEntryFor(allocated_block_header);
        std.debug.assert(entry.node == null);

        const new_node: *AllocatedBlocks.Node = try self.allocated_blocks_node_mempool.create();
        new_node.key = allocated_block_header;
        entry.set(new_node);
    }

    pub fn malloc(self: *Self, requested_size: usize) Error!ErasedPtr {
        if (requested_size <= MAX_SMALL_BLOCK_SIZE) {
            var size = requested_size;
            if (requested_size % BLOCK_SIZE_STEP != 0) {
                size += BLOCK_SIZE_STEP - requested_size % BLOCK_SIZE_STEP;
            }
            const arena_index = getSmallBlockArenaIndex(size);
            const block_ptr = try self.small_arenas[arena_index].getBlock(&self.small_arena_node_mempool);

            try self.markBlockAllocated(block_ptr, size);

            return block_ptr;
        } else if (MAX_SMALL_BLOCK_SIZE < requested_size and requested_size <= MAX_MEDIUM_BLOCK_SIZE) {
            const size = MediumBlockArena.roundSize(requested_size);
            const ptr = try self.medium_arena.getBlock(&self.medium_arena_node_mempool, requested_size);
            try self.markBlockAllocated(ptr, size);
            return ptr;
        } else {
            const size = std.mem.alignForward(usize, requested_size, std.mem.page_size);
            const ptr = (try std.heap.page_allocator.alignedAlloc(u8, std.mem.page_size, size)).ptr;
            try self.markBlockAllocated(ptr, size);
            return ptr;
        }
    }

    pub fn calloc(self: *Self, n: usize, elem_size: usize) Error!ErasedPtr {
        const ptr = try self.malloc(n * elem_size);
        @memset(ptr[0 .. n * elem_size], 0);
        return ptr;
    }

    pub const FreeError = error{
        InvalidAddress,
    };
    pub fn realloc(self: *Self, ptr: *anyopaque, size: usize) !ErasedPtr {
        if (!std.mem.isAligned(@intFromPtr(ptr), BLOCK_ALIGNMENT)) {
            return FreeError.InvalidAddress;
        }

        const ptr_casted: ErasedPtr = @ptrCast(@alignCast(ptr));
        const block_size = self.getBlockSize(ptr_casted);
        if (block_size == null) {
            return FreeError.InvalidAddress;
        }

        if (block_size.? >= size) {}

        const new_data = try self.malloc(size);
        @memcpy(new_data[0..block_size.?], ptr_casted[0..block_size.?]);

        return new_data;
    }

    pub fn free(self: *Self, ptr: *anyopaque) FreeError!void {
        if (!std.mem.isAligned(@intFromPtr(ptr), BLOCK_ALIGNMENT)) {
            return FreeError.InvalidAddress;
        }

        var entry = self.allocated_blocks.getEntryFor(AllocatedBlock{ .payload = @ptrCast(@alignCast(ptr)), .size = undefined });
        if (entry.node == null) {
            return FreeError.InvalidAddress;
        }

        const block = entry.node.?.key;
        entry.set(null);

        if (block.size <= MAX_SMALL_BLOCK_SIZE) {
            const arena_index = getSmallBlockArenaIndex(block.size);
            self.small_arenas[arena_index].returnBlock(block.payload);
        } else if (block.size <= MAX_MEDIUM_BLOCK_SIZE) {
            self.medium_arena.returnBlock(block.payload, block.size);
        } else {
            std.heap.page_allocator.free(block.payload[0..block.size]);            
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
    try std.testing.expectEqual(256, MediumBlockArena.roundSize(142));
    try std.testing.expectEqual(256, MediumBlockArena.roundSize(256));
    try std.testing.expectEqual(512, MediumBlockArena.roundSize(257));
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

test "medium size blocks" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    var p: [*]u8 = try allocator.malloc(MAX_SMALL_BLOCK_SIZE + 15);
    p[MAX_SMALL_BLOCK_SIZE + 14] = 42;
    try allocator.free(p);

    p = try allocator.malloc(MIN_MEDIUM_BLOCK_SIZE * 4);
    p[MIN_MEDIUM_BLOCK_SIZE * 4 - 3] = 42;
    try allocator.free(p);

    p = try allocator.malloc(MAX_MEDIUM_BLOCK_SIZE);
    p[MAX_MEDIUM_BLOCK_SIZE - 3] = 42;
    try allocator.free(p);

    try std.testing.expectEqual(.ok, allocator.detectLeaks());
}

test "large blocks" {
    allocator = SpAllocator.init();
    defer std.debug.assert(allocator.deinit(false) == .ok);

    var p: [*]u8 = try allocator.malloc(MAX_MEDIUM_BLOCK_SIZE + 15);
    p[MAX_MEDIUM_BLOCK_SIZE + 14] = 42;
    try allocator.free(p);

    p = try allocator.malloc(MAX_MEDIUM_BLOCK_SIZE * 2);
    p[MAX_MEDIUM_BLOCK_SIZE * 2 - 3] = 42;
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

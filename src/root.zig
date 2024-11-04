const std = @import("std");
const libc = @cImport(@cInclude("stdlib.h"));

const Error = std.mem.Allocator.Error;

const MIN_BLOCK_SIZE = 16;
const MAX_SMALL_BLOCK_SIZE = 128;
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

fn getMemoryPage() Error!ErasedPtr {
    return (try std.heap.page_allocator.alignedAlloc(u8, std.mem.page_size, std.mem.page_size)).ptr;
}

const SmallBlockArena = struct {
    const NodeMemPool = std.heap.MemoryPool(Chunks.Node);

    const Chunk = struct {
        data: ErasedPtr,

        pub fn getBlocksCount(block_size: usize) usize {
            return std.mem.page_size / block_size;
        }

        pub fn getNthBlock(self: Chunk, block_size: usize, n: usize) *FreeBlock {
            std.debug.assert(block_size * n < std.mem.page_size);

            return @ptrCast(@alignCast(self.data + (block_size * n)));
        }
    };

    // `chunk` is a memory page that gets splitted into blocks
    const Chunks = std.SinglyLinkedList(Chunk);

    block_size: usize,
    chunks: Chunks,
    first_free_block: ?*FreeBlock,

    pub fn init(block_size: usize) SmallBlockArena {
        return SmallBlockArena{
            .chunks = .{},
            .block_size = block_size,
            .first_free_block = null,
        };
    }

    fn addNewChunk(self: *SmallBlockArena, node_mempool: *NodeMemPool) Error!void {
        const new_node: *Chunks.Node = try node_mempool.create();
        const new_chunk = Chunk{ .data = try getMemoryPage() };
        new_node.data = new_chunk;
        self.chunks.prepend(new_node);

        for (0..Chunk.getBlocksCount(self.block_size) - 1) |i| {
            var cur_block = new_chunk.getNthBlock(self.block_size, i);
            cur_block.next = new_chunk.getNthBlock(self.block_size, i + 1);
        }
        new_chunk.getNthBlock(self.block_size, Chunk.getBlocksCount(self.block_size) - 1).next = null;

        self.first_free_block = @ptrCast(@alignCast(new_chunk.data));
    }

    pub fn popBlock(self: *SmallBlockArena, node_mempool: *NodeMemPool) Error!ErasedPtr {
        if (self.first_free_block == null) {
            try self.addNewChunk(node_mempool);
        }

        defer self.first_free_block = self.first_free_block.?.next;
        return @ptrCast(self.first_free_block.?);
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

        const allocated_blocks_node_mempool = AllocatedBlocksNodeMemPool.init(std.heap.page_allocator);

        return Self{
            .small_arena_node_mempool = small_arena_node_mempool,
            .small_arenas = small_block_arenas,
            .allocated_blocks_node_mempool = allocated_blocks_node_mempool,
            .allocated_blocks = AllocatedBlocks{},
        };
    }

    const LeakCheckResult = enum {
        Ok,
        Leak,
    };

    pub fn detectLeaks(self: Self) LeakCheckResult {
        if (self.allocated_blocks.root != null) {
            return .Leak;
        }
        return .Ok;
    }

    pub fn deinit(self: *Self, report_leaks: bool) !LeakCheckResult {
        const result = self.detectLeaks();
        if (result == .Leak and report_leaks) {
            var iter = self.allocated_blocks.inorderIterator();

            while (iter.next()) |node| {
                std.log.err("Memory leak of address 0x{x} detected", .{@intFromPtr(node.key.payload)});
            }
        }

        self.small_arena_node_mempool.deinit();
        self.allocated_blocks_node_mempool.deinit();
        return result;
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

        std.debug.assert(self.allocated_blocks.root.?.key.payload == block_ptr);
    }

    pub fn malloc(self: *Self, requested_size: usize) Error!ErasedPtr {
        var size = requested_size;
        if (requested_size % BLOCK_SIZE_STEP != 0) {
            size += BLOCK_SIZE_STEP - requested_size % BLOCK_SIZE_STEP;
        }

        if (size <= MAX_SMALL_BLOCK_SIZE) {
            const arena_index = size / BLOCK_SIZE_STEP - 1;
            const block_ptr = try self.small_arenas[arena_index].popBlock(&self.small_arena_node_mempool);

            try self.markBlockAllocated(block_ptr, size);

            return block_ptr;
        }

        return Error.OutOfMemory;
    }

    pub fn calloc(self: *Self, n: usize, elem_size: usize) Error!ErasedPtr {
        const ptr = try self.malloc(n * elem_size);
        @memset(ptr[0 .. n * elem_size], 0);
        return ptr;
    }

    pub const FreeError = error{
        InvalidAddress,
    };
    pub fn realloc(self: *Self, ptr: ?*anyopaque, size: usize) !?ErasedPtr {
        if (ptr == null) {
            return null;
        }
        if (!std.mem.isAligned(@intFromPtr(ptr.?), BLOCK_ALIGNMENT)) {
            return FreeError.InvalidAddress;
        }

        const ptr_casted: ErasedPtr = @ptrCast(@alignCast(ptr.?));
        const block_size = self.getBlockSize(ptr_casted);
        if (block_size == null) {
            return FreeError.InvalidAddress;
        }

        const new_data = try self.malloc(size);
        @memcpy(new_data[0..block_size.?], ptr_casted[0..block_size.?]);

        return new_data;
    }

    pub fn free(self: *Self, ptr: ?*anyopaque) FreeError!void {
        if (ptr == null) {
            return;
        }
        if (!std.mem.isAligned(@intFromPtr(ptr.?), BLOCK_ALIGNMENT)) {
            return FreeError.InvalidAddress;
        }

        var entry = self.allocated_blocks.getEntryFor(AllocatedBlock{ .payload = @ptrCast(@alignCast(ptr.?)), .size = undefined });
        if (entry.node == null) {
            return FreeError.InvalidAddress;
        }
        entry.set(null);
    }
};

pub var allocator: SpAllocator = undefined;
var is_allocator_initialized: bool = false;

pub export fn deinitAllocator() callconv(.C) void {
    _ = allocator.deinit(true) catch std.process.abort();
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
            std.log.err("`realloc` of invalid address 0x{x}", .{@intFromPtr(ptr)});
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
            std.log.err("`free` of invalid address 0x{x}", .{@intFromPtr(ptr)});
            std.process.abort();
        },
    };
}

test "basic" {
    allocator = SpAllocator.init();

    const p = try allocator.malloc(16);
    allocator.free(p);

    try std.testing.expectEqual(.Ok, allocator.deinit(false));
}

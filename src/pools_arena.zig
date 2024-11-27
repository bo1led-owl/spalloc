const std = @import("std");
const common = @import("common.zig");
const ErasedPtr = common.ErasedPtr;
const Error = common.Error;

pub const Options = struct {
    min_chunk_size: usize = 16,
    max_chunk_size: usize = 256,
    chunk_size_step: usize = 16,
    block_size: usize = 4 * std.mem.page_size,
};

pub fn PoolsArena(comptime options: Options) type {
    const min_chunk_size = options.min_chunk_size;
    const max_chunk_size = options.max_chunk_size;
    const chunk_size_step = options.chunk_size_step;
    const block_size = options.block_size;
    comptime {
        std.debug.assert(chunk_size_step % 8 == 0);
        std.debug.assert(max_chunk_size >= min_chunk_size);
        std.debug.assert(max_chunk_size % chunk_size_step == 0);
        std.debug.assert(min_chunk_size % chunk_size_step == 0);
    }

    const ChunkPool = struct {
        const Self = @This();
        const FreeChunk = struct {
            next: ?*FreeChunk,
        };

        comptime {
            std.debug.assert(@sizeOf(FreeChunk) <= min_chunk_size);
            std.debug.assert(@alignOf(FreeChunk) == common.CHUNK_ALIGNMENT);
        }

        pub const NodeMemPool = std.heap.MemoryPool(Buffers.Node);

        const Buffer = struct {
            ptr: ErasedPtr,
            after_last_chunk: ErasedPtr,

            pub fn init(allocator: std.mem.Allocator) Error!Buffer {
                const ptr = try common.allocatePages(allocator, block_size);
                return Buffer{
                    .ptr = ptr,
                    .after_last_chunk = ptr,
                };
            }

            pub fn tryAppendChunk(self: *Buffer, chunk_size: usize) ?ErasedPtr {
                if (@intFromPtr(self.ptr + block_size) - @intFromPtr(self.after_last_chunk) < chunk_size) {
                    return null;
                }

                defer self.after_last_chunk = @alignCast(self.after_last_chunk + chunk_size);
                return self.after_last_chunk;
            }

            pub fn getChunksCount(chunk_size: usize) usize {
                std.debug.assert(chunk_size % chunk_size_step == 0);

                return std.mem.page_size / chunk_size;
            }
        };

        const Buffers = std.SinglyLinkedList(Buffer);

        chunk_size: usize,
        buffers: Buffers,
        first_free_chunk: ?*FreeChunk,

        pub fn init(chunk_size: usize) Self {
            return .{
                .buffers = .{},
                .chunk_size = chunk_size,
                .first_free_chunk = null,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            var cur_node = self.buffers.first;
            while (cur_node) |node| : (cur_node = cur_node.?.next) {
                common.freePages(allocator, node.data.ptr, block_size);
            }
        }

        fn addNewBuffer(self: *Self, allocator: std.mem.Allocator, node_mempool: *NodeMemPool) Error!void {
            const new_node: *Buffers.Node = try node_mempool.create();
            const new_buffer = try Buffer.init(allocator);
            new_node.data = new_buffer;
            self.buffers.prepend(new_node);
        }

        pub fn putChunk(self: *Self, ptr: ErasedPtr) void {
            const new_chunk: *FreeChunk = @ptrCast(ptr);
            new_chunk.next = self.first_free_chunk;
            self.first_free_chunk = new_chunk;
        }

        pub fn getChunk(self: *Self, allocator: std.mem.Allocator, node_mempool: *NodeMemPool) Error!ErasedPtr {
            if (self.first_free_chunk) |result| {
                self.first_free_chunk = result.next;
                result.next = null;
                return @ptrCast(result);
            }

            if (self.buffers.first) |first_node| {
                if (first_node.data.tryAppendChunk(self.chunk_size)) |result| {
                    @as(*FreeChunk, @ptrCast(@alignCast(result))).next = null;
                    return result;
                }
            }

            try self.addNewBuffer(allocator, node_mempool);
            const result = self.buffers.first.?.data.tryAppendChunk(self.chunk_size).?;
            @as(*FreeChunk, @ptrCast(@alignCast(result))).next = null;
            return result;
        }
    };

    return struct {
        const Self = @This();

        const POOLS_COUNT = (max_chunk_size - min_chunk_size) / chunk_size_step;

        allocator: std.mem.Allocator,
        pools_node_mempool: ChunkPool.NodeMemPool,
        pools: [POOLS_COUNT]ChunkPool,

        pub fn init(allocator: std.mem.Allocator) Self {
            var pools: [POOLS_COUNT]ChunkPool = [_]ChunkPool{undefined} ** POOLS_COUNT;

            for (0..POOLS_COUNT) |i| {
                const cur_chunk_size = min_chunk_size + i * chunk_size_step;
                std.debug.assert(min_chunk_size <= cur_chunk_size);
                std.debug.assert(cur_chunk_size <= max_chunk_size);

                pools[i] = ChunkPool.init(cur_chunk_size);
            }

            const pools_node_mempool = ChunkPool.NodeMemPool.init(allocator);

            return Self{
                .allocator = allocator,
                .pools = pools,
                .pools_node_mempool = pools_node_mempool,
            };
        }

        pub fn deinit(self: *Self) void {
            for (&self.pools) |*pool| {
                pool.deinit(self.allocator);
            }
            self.pools_node_mempool.deinit();
        }

        pub fn chunkFits(chunk_size: usize) bool {
            return chunk_size <= max_chunk_size;
        }

        pub fn getChunk(self: *Self, chunk_size: usize) Error!common.Chunk {
            std.debug.assert(Self.chunkFits(chunk_size));

            const rounded_size = if (chunk_size < min_chunk_size)
                min_chunk_size
            else
                chunk_size + chunk_size_step - (chunk_size - min_chunk_size) % chunk_size_step;
            const pool_index = (rounded_size - min_chunk_size) / chunk_size_step;
            return common.Chunk{
                .ptr = try self.pools[pool_index].getChunk(self.allocator, &self.pools_node_mempool),
                .size = rounded_size,
            };
        }

        pub fn putChunk(self: *Self, chunk: common.Chunk) void {
            std.debug.assert(Self.chunkFits(chunk.size));
            std.debug.assert(chunk.size >= min_chunk_size);
            std.debug.assert(std.mem.isAligned(chunk.size, chunk_size_step));

            const pool_index = (chunk.size - min_chunk_size) / chunk_size_step;
            self.pools[pool_index].putChunk(chunk.ptr);
        }
    };
}

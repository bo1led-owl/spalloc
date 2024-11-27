const std = @import("std");

const common = @import("common.zig");
const ErasedPtr = common.ErasedPtr;
const Error = common.Error;

pub const Options = struct {
    min_chunk_size: usize = 512,
    max_chunk_size: usize = 32 * common.KiB,
};

pub fn BuddySystemArena(comptime options: Options) type {
    const min_chunk_size = options.min_chunk_size;
    const max_chunk_size = options.max_chunk_size;
    comptime {
        std.debug.assert(max_chunk_size % min_chunk_size == 0);
        std.debug.assert(std.math.isPowerOfTwo(max_chunk_size / min_chunk_size));
    }
    return struct {
        const Self = @This();

        const Buffer = struct {
            const SIZE = max_chunk_size;

            header: Header,
            ptr: ErasedPtr,

            const Header = struct {
                const SMALLEST_CHUNKS_COUNT = max_chunk_size / min_chunk_size;
                const BITS = 2 * SMALLEST_CHUNKS_COUNT - 1;

                const ReprType = std.StaticBitSet(BITS);
                const IndexType = std.math.IntFittingRange(0, SMALLEST_CHUNKS_COUNT);

                repr: ReprType,

                fn chunkHasChildren(index: IndexType) bool {
                    return (index + 1) < SMALLEST_CHUNKS_COUNT;
                }

                fn areChildrenFree(self: Header, index: IndexType) bool {
                    if (!chunkHasChildren(index)) {
                        return true;
                    }

                    const l_child = 2 * (index + 1) - 1;
                    const r_child = 2 * (index + 1) + 1 - 1;
                    return !self.repr.isSet(l_child) and !self.repr.isSet(r_child) and
                        self.areChildrenFree(l_child) and self.areChildrenFree(r_child);
                }

                fn areParentsFree(self: Header, index: IndexType) bool {
                    var i = (index + 1) / 2;
                    while (i > 0) : (i /= 2) {
                        if (self.repr.isSet(i - 1)) {
                            return false;
                        }
                    }

                    return true;
                }

                pub fn isChunkFree(self: Header, index: IndexType) bool {
                    return !self.repr.isSet(index) and
                        self.areChildrenFree(index) and
                        self.areParentsFree(index);
                }

                pub fn markChunkFree(self: *Header, index: IndexType) void {
                    self.repr.setValue(index, false);
                }

                pub fn markChunkAllocated(self: *Header, index: IndexType) void {
                    self.repr.set(index);
                }
            };

            pub fn init(allocator: std.mem.Allocator) Error!Buffer {
                return Buffer{
                    .header = .{ .repr = Header.ReprType.initEmpty() },
                    .ptr = try common.allocatePages(allocator, SIZE),
                };
            }

            pub fn getChunk(self: *Buffer, size: usize) ?ErasedPtr {
                std.debug.assert(size >= min_chunk_size);
                std.debug.assert(size <= max_chunk_size);
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

            pub fn putChunk(self: *Buffer, chunk: common.Chunk) void {
                std.debug.assert(self.ownsChunk(chunk.ptr));
                std.debug.assert(chunk.size >= min_chunk_size);
                std.debug.assert(chunk.size <= max_chunk_size);
                std.debug.assert(std.math.isPowerOfTwo(chunk.size / min_chunk_size));

                const index: u6 = @intCast((@intFromPtr(chunk.ptr) - @intFromPtr(self.ptr)) / chunk.size);
                self.header.markChunkFree(index);
            }

            pub fn ownsChunk(self: Buffer, ptr: ErasedPtr) bool {
                return @intFromPtr(ptr) >= @intFromPtr(self.ptr) and
                    @intFromPtr(ptr) - @intFromPtr(self.ptr) <= Buffer.SIZE;
            }

            pub fn tryResizeChunk(self: *Buffer, chunk: ErasedPtr, cur_size: usize, new_size: usize) ?ErasedPtr {
                std.debug.assert(cur_size < new_size);

                const original_chunk: u7 = @intCast(Buffer.SIZE / cur_size + (@intFromPtr(chunk) - @intFromPtr(self.ptr)) / cur_size);

                const chunks_to_check = Buffer.SIZE / new_size;
                const starting_index = chunks_to_check - 1;

                // to not obstruct the checks later
                self.header.markChunkFree(original_chunk);

                var result_ptr: ?ErasedPtr = null;
                var result_index: Header.IndexType = undefined;
                var min_dist: usize = std.math.maxInt(usize);
                const original_chunk_int_ptr = @intFromPtr(chunk);
                for (starting_index..(starting_index + chunks_to_check)) |i| {
                    if (!self.header.repr.isSet(@intCast(i)) and self.header.areChildrenFree(@intCast(i))) {
                        const cur_chunk_ptr: ErasedPtr = @alignCast(self.ptr + new_size * (i - starting_index));
                        const cur_chunk_int_ptr = @intFromPtr(cur_chunk_ptr);

                        if (original_chunk_int_ptr == cur_chunk_int_ptr) {
                            self.header.markChunkAllocated(@intCast(i));
                            return chunk;
                        }

                        const dist = if (original_chunk_int_ptr < cur_chunk_int_ptr) cur_chunk_int_ptr - original_chunk_int_ptr else original_chunk_int_ptr - cur_chunk_int_ptr;
                        if (dist < min_dist) {
                            min_dist = dist;
                            result_ptr = cur_chunk_ptr;
                            result_index = @intCast(i);
                        }
                    }
                }

                if (result_ptr) |ptr| {
                    common.memmove(u8, ptr[0..cur_size], chunk[0..cur_size]);
                    self.header.markChunkAllocated(@intCast(result_index));
                    return ptr;
                }

                self.header.markChunkAllocated(@intCast(original_chunk));
                return null;
            }
        };

        const Buffers = std.SinglyLinkedList(Buffer);
        pub const NodeMemPool = std.heap.MemoryPool(Buffers.Node);

        allocator: std.mem.Allocator,
        node_mempool: NodeMemPool,
        buffers: Buffers = .{},

        pub fn init(allocator: std.mem.Allocator) Self {
            return Self{
                .allocator = allocator,
                .node_mempool = NodeMemPool.init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            var cur_node = self.buffers.first;
            while (cur_node) |node| : (cur_node = cur_node.?.next) {
                common.freePages(self.allocator, node.data.ptr, Buffer.SIZE);
            }
            self.node_mempool.deinit();
        }

        pub fn putChunk(self: *Self, chunk: common.Chunk) void {
            var cur_node = self.buffers.first;
            while (cur_node) |node| {
                if (node.data.ownsChunk(chunk.ptr)) {
                    node.data.putChunk(chunk);
                    return;
                }

                cur_node = node.next;
            }

            unreachable;
        }

        pub fn chunkFits(size: usize) bool {
            return size <= max_chunk_size;
        }

        pub fn roundSize(size: usize) usize {
            const shift = std.math.log2_int_ceil(usize, size);
            return std.math.shl(usize, @as(usize, @intCast(1)), shift);
        }

        fn addNewBuffer(self: *Self) Error!*Buffer {
            const new_node = try self.node_mempool.create();
            new_node.data = try Buffer.init(self.allocator);
            self.buffers.prepend(new_node);

            return &self.buffers.first.?.data;
        }

        pub fn getChunk(self: *Self, requested_size: usize) Error!common.Chunk {
            const rounded_size = roundSize(requested_size);

            var cur_node = self.buffers.first;
            while (cur_node) |node| {
                if (node.data.getChunk(rounded_size)) |ptr| {
                    return common.Chunk{ .ptr = ptr, .size = rounded_size };
                }
                cur_node = node.next;
            }

            // couldn't find any chunks, have to add new buffer
            var new_buffer = try self.addNewBuffer();
            return common.Chunk{ .ptr = new_buffer.getChunk(rounded_size).?, .size = rounded_size };
        }

        pub fn tryResizeChunk(self: *Self, chunk: ErasedPtr, cur_size: usize, new_size: usize) ?common.Chunk {
            const rounded_size = Self.roundSize(new_size);

            var cur_node = self.buffers.first;
            while (cur_node) |node| : (cur_node = cur_node.?.next) {
                if (node.data.ownsChunk(chunk)) {
                    const ptr = node.data.tryResizeChunk(chunk, cur_size, rounded_size);
                    if (ptr == null) {
                        return null;
                    }

                    return common.Chunk{ .ptr = ptr.?, .size = rounded_size };
                }
            }

            unreachable;
        }
    };
}

test "round size" {
    try std.testing.expectEqual(256, BuddySystemArena(.{}).roundSize(142));
    try std.testing.expectEqual(256, BuddySystemArena(.{}).roundSize(256));
    try std.testing.expectEqual(512, BuddySystemArena(.{}).roundSize(257));
}

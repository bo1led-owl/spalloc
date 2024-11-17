const Self = @This();

const std = @import("std");

const common = @import("common.zig");
const ErasedPtr = common.ErasedPtr;
const Error = common.Error;

const consts = common.consts;
const MAX_SMALL_CHUNK_SIZE = @import("SmallChunkPool.zig").MAX_CHUNK_SIZE;

pub const MIN_CHUNK_SIZE = MAX_SMALL_CHUNK_SIZE * 2;
pub const MAX_CHUNK_SIZE = 32 * common.KiB;

const Buffer = struct {
    const SIZE = MAX_CHUNK_SIZE;

    header: Header,
    ptr: ErasedPtr,

    const Header = struct {
        const SMALLEST_CHUNKS_COUNT = MAX_CHUNK_SIZE / MIN_CHUNK_SIZE;
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

    pub fn init() Error!Buffer {
        return Buffer{
            .header = .{ .repr = Header.ReprType.initEmpty() },
            .ptr = try common.requestMemoryFromOS(SIZE),
        };
    }

    pub fn getChunk(self: *Buffer, size: usize) ?ErasedPtr {
        std.debug.assert(size >= MIN_CHUNK_SIZE);
        std.debug.assert(size <= MAX_CHUNK_SIZE);
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
        std.debug.assert(size >= MIN_CHUNK_SIZE);
        std.debug.assert(size <= MAX_CHUNK_SIZE);
        std.debug.assert(@popCount(size) == 1);

        const index: u6 = @intCast((@intFromPtr(ptr) - @intFromPtr(self.ptr)) / size);
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

buffers: Buffers = .{},

pub fn deinit(self: *Self) void {
    var cur_node = self.buffers.first;
    while (cur_node) |node| : (cur_node = cur_node.?.next) {
        common.returnMemoryToOS(node.data.ptr, Buffer.SIZE);
    }
}

pub fn putChunk(self: *Self, ptr: ErasedPtr, size: usize) void {
    var cur_node = self.buffers.first;
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

fn addNewBuffer(self: *Self, node_mempool: *NodeMemPool) Error!*Buffer {
    const new_node = try node_mempool.create();
    new_node.data = try Buffer.init();
    self.buffers.prepend(new_node);

    return &self.buffers.first.?.data;
}

pub fn getChunk(self: *Self, node_mempool: *NodeMemPool, requested_size: usize) Error!ErasedPtr {
    const size = roundSize(requested_size);

    var cur_node = self.buffers.first;
    while (cur_node) |node| {
        if (node.data.getChunk(size)) |ptr| {
            return ptr;
        }
        cur_node = node.next;
    }

    // couldn't find any chunks, have to add new buffer
    var new_buffer = try self.addNewBuffer(node_mempool);
    return new_buffer.getChunk(size).?;
}

pub fn tryResizeChunk(self: *Self, chunk: ErasedPtr, cur_size: usize, new_size: usize) ?ErasedPtr {
    var cur_node = self.buffers.first;
    while (cur_node) |node| : (cur_node = cur_node.?.next) {
        if (node.data.ownsChunk(chunk)) {
            return node.data.tryResizeChunk(chunk, cur_size, new_size);
        }
    }

    unreachable;
}

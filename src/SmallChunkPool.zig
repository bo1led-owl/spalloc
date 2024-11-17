const Self = @This();

const std = @import("std");
const common = @import("common.zig");
const ErasedPtr = common.ErasedPtr;
const Error = common.Error;

const consts = common.consts;

pub const CHUNK_SIZE_STEP = 16;
pub const MIN_CHUNK_SIZE = 16;
pub const MAX_CHUNK_SIZE = 256;

const FreeChunk = struct {
    next: ?*FreeChunk,
};

comptime {
    std.debug.assert(@sizeOf(FreeChunk) <= MIN_CHUNK_SIZE);
    std.debug.assert(@alignOf(FreeChunk) == consts.CHUNK_ALIGNMENT);
}

pub const NodeMemPool = std.heap.MemoryPool(Buffers.Node);

const Buffer = struct {
    const SIZE = 4 * std.mem.page_size;

    ptr: ErasedPtr,
    after_last_chunk: ErasedPtr,

    pub fn init() Error!Buffer {
        const ptr = try common.getMemoryPages(SIZE / std.mem.page_size);
        return Buffer{
            .ptr = ptr,
            .after_last_chunk = ptr,
        };
    }

    pub fn tryAppendChunk(self: *Buffer, chunk_size: usize) ?ErasedPtr {
        if (@intFromPtr(self.ptr + SIZE) - @intFromPtr(self.after_last_chunk) < chunk_size) {
            return null;
        }

        defer self.after_last_chunk = @alignCast(self.after_last_chunk + chunk_size);
        return self.after_last_chunk;
    }

    pub fn getChunksCount(chunk_size: usize) usize {
        std.debug.assert(chunk_size % consts.CHUNK_SIZE_STEP == 0);

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

pub fn deinit(self: *Self) void {
    var cur_node = self.buffers.first;
    while (cur_node) |node| : (cur_node = cur_node.?.next) {
        std.heap.page_allocator.free(node.data.ptr[0..Buffer.SIZE]);
    }
}

fn addNewBuffer(self: *Self, node_mempool: *NodeMemPool) Error!void {
    const new_node: *Buffers.Node = try node_mempool.create();
    const new_buffer = try Buffer.init();
    new_node.data = new_buffer;
    self.buffers.prepend(new_node);
}

pub fn putChunk(self: *Self, ptr: ErasedPtr) void {
    const new_chunk: *FreeChunk = @ptrCast(ptr);
    new_chunk.next = self.first_free_chunk;
    self.first_free_chunk = new_chunk;
}

pub fn getChunk(self: *Self, node_mempool: *NodeMemPool) Error!ErasedPtr {
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

    try self.addNewBuffer(node_mempool);
    const result = self.buffers.first.?.data.tryAppendChunk(self.chunk_size).?;
    @as(*FreeChunk, @ptrCast(@alignCast(result))).next = null;
    return result;
}

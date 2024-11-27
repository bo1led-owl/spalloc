const common = @import("common.zig");

pub const MIN_SMALL_CHUNK_SIZE = 16;
pub const MAX_SMALL_CHUNK_SIZE = 256;
pub const SMALL_CHUNK_SIZE_STEP = 16;
pub const MIN_MEDIUM_CHUNK_SIZE = SMALL_CHUNK_SIZE_STEP * 2;
pub const MAX_MEDIUM_CHUNK_SIZE = 32 * common.KiB;

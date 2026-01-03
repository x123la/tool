const std = @import("std");

pub const ProcStat = struct {
    starttime: u64, // ticks
    comm: []u8, // owned slice
    state: u8,
    
    pub fn deinit(self: ProcStat, allocator: std.mem.Allocator) void {
        allocator.free(self.comm);
    }
};

pub fn get_pid_starttime(allocator: std.mem.Allocator, pid: i32) !u64 {
    const path = try std.fmt.allocPrint(allocator, "/proc/{d}/stat", .{pid});
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
        if (err == error.FileNotFound) return error.PidNotFound;
        return err;
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 4096);
    defer allocator.free(content);

    // Find last ')'
    const last_rparen = std.mem.lastIndexOfScalar(u8, content, ')');
    if (last_rparen == null) return error.ParseError;

    const rest = content[last_rparen.? + 2 ..]; // skip ") "
    var it = std.mem.splitScalar(u8, rest, ' ');

    var index: usize = 0;
    while (it.next()) |token| : (index += 1) {
        if (index == 19) { // 22nd field overall -> 19th after state (#3)
            return std.fmt.parseInt(u64, token, 10);
        }
    }
    return error.ParseError;
}

pub fn get_cmdline(allocator: std.mem.Allocator, pid: i32) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "/proc/{d}/cmdline", .{pid});
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
        // Fallback to comm
        if (err == error.FileNotFound) return get_comm(allocator, pid);
        return err; // Other permissions errors
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 4);
    // Replace nulls with spaces
    for (content) |*b| {
        if (b.* == 0) b.* = ' ';
    }
    
    // Trim trailing space if exists
    // actually, cmdline often ends with null.
    // If empty, fallback
    if (content.len == 0) {
        allocator.free(content);
        return get_comm(allocator, pid);
    }
    
    return content;
}

fn get_comm(allocator: std.mem.Allocator, pid: i32) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "/proc/{d}/comm", .{pid});
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch return error.PidNotFound; // or unknown
    defer file.close();

    var content = try file.readToEndAlloc(allocator, 256);
    // Remove trailing newline
    if (content.len > 0 and content[content.len - 1] == '\n') {
        const trimmed = try allocator.dupe(u8, content[0..content.len-1]);
        allocator.free(content);
        return trimmed;
    }
    return content;
}

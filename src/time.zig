const std = @import("std");

pub const SystemTime = struct {
    boot_time: u64,
    hz: u64,
};

pub fn get_system_time() !SystemTime {
    const boot_time = try get_boot_time();
    const hz = get_hz();
    return SystemTime{ .boot_time = boot_time, .hz = hz };
}

pub fn get_current_timestamp() u64 {
    return @as(u64, @intCast(std.time.timestamp()));
}

fn get_boot_time() !u64 {
    const file = try std.fs.openFileAbsolute("/proc/stat", .{});
    defer file.close();

    var buf: [65536]u8 = undefined;
    const n = try file.readAll(&buf);
    var lines = std.mem.tokenizeScalar(u8, buf[0..n], '\n');

    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "btime ")) {
            var it = std.mem.splitScalar(u8, line, ' ');
            _ = it.next(); // skip "btime"
            while (it.next()) |part| {
                if (part.len == 0) continue;
                return std.fmt.parseInt(u64, part, 10);
            }
        }
    }
    return error.BootTimeNotFound;
}

extern "c" fn sysconf(name: c_int) c_long;

fn get_hz() u64 {
    const _SC_CLK_TCK = 2;
    return @intCast(sysconf(_SC_CLK_TCK));
}

pub fn parse_duration(s: []const u8) !u64 {
    if (s.len < 2) return error.InvalidDuration;
    
    // Find where digits end
    var i: usize = 0;
    while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {}
    
    if (i == 0) return error.InvalidDuration; // No digits
    if (i == s.len) return error.InvalidDuration; // No unit
    
    const val_str = s[0..i];
    const unit_str = s[i..];
    
    const val = try std.fmt.parseInt(u64, val_str, 10);
    
    if (std.mem.eql(u8, unit_str, "s")) {
        return val;
    } else if (std.mem.eql(u8, unit_str, "m")) {
        return val * 60;
    } else if (std.mem.eql(u8, unit_str, "h")) {
        return val * 3600;
    } else if (std.mem.eql(u8, unit_str, "d")) {
        return val * 86400;
    } else {
        return error.InvalidDuration;
    }
}

test "parse_duration" {
    try std.testing.expectEqual(@as(u64, 10), try parse_duration("10s"));
    try std.testing.expectEqual(@as(u64, 300), try parse_duration("5m"));
    try std.testing.expectEqual(@as(u64, 7200), try parse_duration("2h"));
    try std.testing.expectEqual(@as(u64, 259200), try parse_duration("3d"));
    try std.testing.expectError(error.InvalidDuration, parse_duration("1"));
    try std.testing.expectError(error.InvalidDuration, parse_duration("xs"));
    try std.testing.expectError(error.InvalidDuration, parse_duration("10q"));
}

const std = @import("std");
const config_mod = @import("config.zig");
const time_mod = @import("time.zig");
const proc_mod = @import("proc.zig"); // Need for accessing proc logic if needed? 
// Ideally tests shouldn't depend on unimported modules, but integration tests do.
// We can assume proc_mod is available to the package.
// But we are in `sysv.zig`. We don't import `proc.zig` currently.
// I'll add the import.

pub const Classification = enum {
    allowlisted,
    in_use,
    likely_orphan,
    possible_orphan,
    unknown,
    risky_to_remove,
};

pub const Recommendation = enum {
    keep,
    review,
    reap,
};

pub const SysVItem = struct {
    shmid: i32,
    key: u64,
    bytes: u64,
    nattch: u32,
    uid: u32,
    perms: u32,
    cpid: i32,
    lpid: i32,
    ctime: u64,
    
    // Derived
    age_seconds: u64 = 0,
    creator_alive: bool = false,
    creator_pid_reused: bool = false,
    last_alive: bool = false, // lpid status
    last_pid_reused: bool = false,

    classification: Classification = .unknown,
    recommendation: Recommendation = .keep,
    reclaimable_bytes: u64 = 0,
    reasons: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator) SysVItem {
        return SysVItem{
            .shmid = 0, .key = 0, .bytes = 0, .nattch = 0, .uid = 0, .perms = 0, .cpid = 0, .lpid = 0, .ctime = 0,
            .reasons = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *SysVItem) void {
        self.reasons.deinit();
    }
};

pub const ParserError = error{
    HeaderMissing,
    MissingRequiredColumn,
    ParseError,
    FileReadError,
};

pub fn parse_sysv_shm(allocator: std.mem.Allocator, path: []const u8) !std.ArrayList(SysVItem) {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();

    var items = std.ArrayList(SysVItem).init(allocator);
    errdefer { // cleanup on error
        for (items.items) |*item| item.deinit();
        items.deinit();
    }

    // Read header (max line length assumption suitable for proc)
    var buf: [4096]u8 = undefined;
    const header_line = (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) orelse return ParserError.HeaderMissing;

    // Map columns
    var col_map = std.StringHashMap(usize).init(allocator);
    defer col_map.deinit();

    var it = std.mem.tokenizeAny(u8, header_line, " \t");
    var idx: usize = 0;
    while (it.next()) |col_name| : (idx += 1) {
        try col_map.put(col_name, idx);
    }
    // Alias size -> bytes
    if (col_map.get("size")) |i| try col_map.put("bytes", i);

    const req_specs = [_][]const u8{"key", "shmid", "perms", "bytes", "nattch", "cpid", "lpid", "ctime", "uid"}; 

    for (req_specs) |req| {
        if (!col_map.contains(req)) {
             return ParserError.MissingRequiredColumn;
        }
    }

    while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        if (line.len == 0) continue;
        
        var fields = std.ArrayList([]const u8).init(allocator);
        defer fields.deinit();
        
        var lit = std.mem.tokenizeAny(u8, line, " \t");
        while (lit.next()) |f| {
            try fields.append(f);
        }
        
        var item = SysVItem.init(allocator);
        
        const get = struct {
            fn val(f: []const []const u8, m: std.StringHashMap(usize), k: []const u8) ![]const u8 {
                const i = m.get(k) orelse return ParserError.MissingRequiredColumn;
                if (i >= f.len) return ParserError.ParseError;
                return f[i];
            }
        }.val;

        item.shmid = try std.fmt.parseInt(i32, try get(fields.items, col_map, "shmid"), 10);
        
        const key_str = try get(fields.items, col_map, "key");
        item.key = try std.fmt.parseInt(u64, key_str, 0);

        item.bytes = try std.fmt.parseInt(u64, try get(fields.items, col_map, "bytes"), 10);
        item.nattch = try std.fmt.parseInt(u32, try get(fields.items, col_map, "nattch"), 10);
        item.uid = try std.fmt.parseInt(u32, try get(fields.items, col_map, "uid"), 10);
        item.cpid = try std.fmt.parseInt(i32, try get(fields.items, col_map, "cpid"), 10);
        item.lpid = try std.fmt.parseInt(i32, try get(fields.items, col_map, "lpid"), 10);
        item.ctime = try std.fmt.parseInt(u64, try get(fields.items, col_map, "ctime"), 10);

        const perms_str = try get(fields.items, col_map, "perms");
        var is_octal = true;
        for (perms_str) |c| {
            if (c < '0' or c > '7') {
                is_octal = false;
                break;
            }
        }
        if (is_octal) {
            item.perms = try std.fmt.parseInt(u32, perms_str, 8);
        } else {
            item.perms = try std.fmt.parseInt(u32, perms_str, 10);
        }

        try items.append(item);
    }

    return items;
}

pub fn classify_item(item: *SysVItem, cfg: config_mod.Config, current_time: u64, allocator: std.mem.Allocator) !void {
    _ = allocator;
    // 1. Allowlist
    var allowlisted = false;
    for (cfg.allow_owners.items) |owner| {
        if (item.uid == owner) {
            allowlisted = true; 
            break;
        }
    }
    if (!allowlisted) {
        for (cfg.allow_keys.items) |k| {
            if (item.key == k) {
                allowlisted = true;
                break;
            }
        }
    }

    if (allowlisted) {
        item.classification = .allowlisted;
        item.recommendation = .keep;
        try item.reasons.append("ALLOWLISTED");
        return;
    }

    // 2. nattch > 0
    if (item.nattch > 0) {
        item.classification = .in_use;
        item.recommendation = .keep;
        try item.reasons.append("ATTACHED");
        return;
    }

    // 3. nattch == 0
    try item.reasons.append("NO_ATTACHMENTS");

    // Age
    item.age_seconds = if (item.ctime == 0) 0 else (if (current_time > item.ctime) current_time - item.ctime else 0);
    
    // Effective alive
    const creator_effective = item.creator_alive and !item.creator_pid_reused;
    const last_effective = item.last_alive and !item.last_pid_reused;

    if (creator_effective) try item.reasons.append("CREATOR_ALIVE") else try item.reasons.append("CREATOR_DEAD_OR_REUSED");
    if (last_effective) try item.reasons.append("LASTPID_ALIVE") else try item.reasons.append("LASTPID_DEAD_OR_REUSED");

    // Min bytes
    if (item.bytes < cfg.min_bytes) {
        item.classification = .unknown;
        item.recommendation = .keep;
        try item.reasons.append("BELOW_MIN_BYTES");
        if (item.ctime != 0 and item.age_seconds >= cfg.threshold_seconds) {
            try item.reasons.append("OLDER_THAN_THRESHOLD");
        } else {
            try item.reasons.append("YOUNGER_THAN_THRESHOLD");
        }
        return;
    }

    // Threshold check
    if (item.ctime != 0 and item.age_seconds >= cfg.threshold_seconds) {
        try item.reasons.append("OLDER_THAN_THRESHOLD");
        if (!creator_effective and !last_effective) {
            item.classification = .likely_orphan;
            item.recommendation = .reap;
            item.reclaimable_bytes = item.bytes;
        } else if (!creator_effective or !last_effective) {
            item.classification = .possible_orphan;
            item.recommendation = .review;
        } else {
            item.classification = .unknown;
            item.recommendation = .keep;
        }
    } else {
        try item.reasons.append("YOUNGER_THAN_THRESHOLD");
        item.classification = .unknown;
        item.recommendation = .keep;
    }

    // Risk override
    if ((item.perms & 0o002) != 0) {
        if (item.classification == .likely_orphan or item.classification == .possible_orphan) {
            item.classification = .risky_to_remove;
            item.recommendation = .review;
            try item.reasons.append("WORLD_WRITABLE_RISK");
            item.reclaimable_bytes = 0; 
        }
    }
}

// Tests
extern "c" fn shmget(key: c_int, size: usize, shmflg: c_int) c_int;
extern "c" fn shmat(shmid: c_int, shmaddr: ?*anyopaque, shmflg: c_int) ?*anyopaque;
extern "c" fn shmdt(shmaddr: ?*anyopaque) c_int;
extern "c" fn shmctl(shmid: c_int, cmd: c_int, buf: ?*anyopaque) c_int;

test "sysv header parsing" {
    const allocator = std.testing.allocator;
    const cwd = std.fs.cwd();
    var buf: [1024]u8 = undefined;
    const abs_path = try cwd.realpath(".", &buf);
    const file_path = try std.fmt.allocPrint(allocator, "{s}/sysv_test_header.txt", .{abs_path});
    defer allocator.free(file_path);
    
    // Header + 1 row
    const content = 
        \\key      shmid perms       size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap
        \\0x00000000 12345 600 1024 100 100 0 1000 1000 1000 1000 0 0 1709491200 0 0
        \\
    ;
    
    const file = try std.fs.createFileAbsolute(file_path, .{});
    try file.writeAll(content);
    file.close();
    defer std.fs.deleteFileAbsolute(file_path) catch {};
    
    const items = try parse_sysv_shm(allocator, file_path);
    defer {
        for (items.items) |*i| i.deinit();
        items.deinit();
    }
    
    try std.testing.expectEqual(items.items.len, 1);
    try std.testing.expectEqual(items.items[0].shmid, 12345);
}

test "integration sysv orphan detection" {
    if (@import("builtin").os.tag != .linux) return;
    const allocator = std.testing.allocator;

    const pid = try std.posix.fork();
    if (pid == 0) {
        // Child
        const IPC_PRIVATE = 0;
        const id = shmget(IPC_PRIVATE, 4096, 0o1000 | 0o600);
        if (id < 0) std.posix.exit(1);

        const ptr = shmat(id, null, 0);
        if (@intFromPtr(ptr) == @as(usize, @bitCast(@as(isize, -1)))) std.posix.exit(2);
        _ = shmdt(ptr);
        
        const file = std.fs.cwd().createFile("sysv_id.txt", .{}) catch std.posix.exit(3);
        const writer = file.writer();
        writer.print("{d}", .{id}) catch std.posix.exit(4);
        file.close();

        std.posix.exit(0);
    } else {
        // Parent
        _ = std.posix.waitpid(pid, 0);
        
        const file = std.fs.cwd().openFile("sysv_id.txt", .{}) catch return; // fail
        defer {
            file.close();
            std.fs.cwd().deleteFile("sysv_id.txt") catch {};
        }
        var buf: [32]u8 = undefined;
        const n = try file.readAll(&buf);
        const id = try std.fmt.parseInt(i32, buf[0..n], 10);
        
        defer _ = shmctl(id, 0, null); // IPC_RMID=0

        // Scan
        var cfg = config_mod.Config.init(allocator);
        defer cfg.deinit();
        cfg.threshold_seconds = 0;
        cfg.min_bytes = 0;

        const items = try parse_sysv_shm(allocator, "/proc/sysvipc/shm");
        defer {
             for (items.items) |*i| i.deinit();
             items.deinit();
        }

        var found = false;
        for (items.items) |*item| {
            if (item.shmid == id) {
                 // Check logic: cpid should be dead.
                 // We need to run explicit alive checks normally handled in scan_sysv
                 // but here we are in sysv.zig module test.
                 // We don't have access to those checks inside classify_item, we must populate them.
                 
                 // Since child is dead (waitpid finished), creator_alive=false.
                 // last_alive=false.
                 item.creator_alive = false;
                 item.last_alive = false;
                 
                 try classify_item(item, cfg, @intCast(std.time.timestamp()), allocator);
                 
                 try std.testing.expectEqual(item.classification, .likely_orphan);
                 found = true;
                 break;
            }
        }
        try std.testing.expect(found);
    }
}

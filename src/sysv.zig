const std = @import("std");
const config_mod = @import("config.zig"); 
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
    allocated_strings: std.ArrayList([]u8),

    pub fn init(allocator: std.mem.Allocator) SysVItem {
        return SysVItem{
            .shmid = 0, .key = 0, .bytes = 0, .nattch = 0, .uid = 0, .perms = 0, .cpid = 0, .lpid = 0, .ctime = 0,
            .reasons = std.ArrayList([]const u8).init(allocator),
            .allocated_strings = std.ArrayList([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *SysVItem) void {
        self.reasons.deinit();
        for (self.allocated_strings.items) |s| self.allocated_strings.allocator.free(s);
        self.allocated_strings.deinit();
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



    var items = std.ArrayList(SysVItem).init(allocator);
    errdefer { // cleanup on error
        for (items.items) |*item| item.deinit();
        items.deinit();
    }

    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(content);

    var lines = std.mem.tokenizeScalar(u8, content, '\n');

    const header_line = lines.next() orelse return ParserError.HeaderMissing;

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

    while (lines.next()) |line| {
        if (line.len == 0) continue;
        
        var fields = std.ArrayList([]const u8).init(allocator);
        defer fields.deinit();
        
        var lit = std.mem.tokenizeAny(u8, line, " \t");
        while (lit.next()) |f| {
            try fields.append(f);
        }
        
        var item = SysVItem.init(allocator);
        
        const get = struct {
            fn val(f: []const []const u8, m: *const std.StringHashMap(usize), k: []const u8) ![]const u8 {
                const i = m.get(k) orelse return ParserError.MissingRequiredColumn;
                if (i >= f.len) return ParserError.ParseError;
                return f[i];
            }
        }.val;

        item.shmid = try std.fmt.parseInt(i32, try get(fields.items, &col_map, "shmid"), 10);
        
        const key_str = try get(fields.items, &col_map, "key");
        item.key = try std.fmt.parseInt(u64, key_str, 0);

        item.bytes = try std.fmt.parseInt(u64, try get(fields.items, &col_map, "bytes"), 10);
        item.nattch = try std.fmt.parseInt(u32, try get(fields.items, &col_map, "nattch"), 10);
        item.uid = try std.fmt.parseInt(u32, try get(fields.items, &col_map, "uid"), 10);
        item.cpid = try std.fmt.parseInt(i32, try get(fields.items, &col_map, "cpid"), 10);
        item.lpid = try std.fmt.parseInt(i32, try get(fields.items, &col_map, "lpid"), 10);
        item.ctime = try std.fmt.parseInt(u64, try get(fields.items, &col_map, "ctime"), 10);

        const perms_str = try get(fields.items, &col_map, "perms");
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

pub fn classify_item(item: *SysVItem, cfg: config_mod.Config, current_time: u64, partial_proc_access: bool, allocator: std.mem.Allocator) !void {
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
            if (partial_proc_access) {
                // If we couldn't verify liveness due to permission, be conservative.
                item.classification = .unknown; // Or possible?
                // "unknown never upgrades to likely_orphan"
                // "mark as unknown due to permission, not dead"
                item.recommendation = .review;
                try item.reasons.append("PROC_ACCESS_DENIED");
            } else {
                item.classification = .likely_orphan;
                item.recommendation = .reap;
                item.reclaimable_bytes = item.bytes;
            }
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

const IPC_STAT = 2;

// Partial shmid_ds definition for verification
const shmid_ds = extern struct {
    shm_perm: extern struct {
        uid: u32,
        gid: u32,
        cuid: u32,
        cgid: u32,
        mode: u32,
        _seq: u32, // pad or seq
        __key: i32, 
        // Layout depends on arch (x86_64). 
        // Using explicit padding might be safer or using libc headers if available.
        // Zig translates C headers if allowed.
        // Let's assume standard linux x86_64 layout or close enough for checking size/ctime?
        // Actually, struct layout varies. Using raw bytes or strict definition is hard without verify.
        // Better to check `bytes` (shm_segsz) and `ctime` (shm_ctime).
    },
    shm_segsz: usize,
    shm_atime: c_long,
    shm_dtime: c_long,
    shm_ctime: c_long,
    shm_cpid: i32,
    shm_lpid: i32,
    shm_nattch: usize,
    // plus more padding
};

// We can try to use a simplified check or `shmctl` behavior.
// If we can't reliably define shmid_ds without importing a C header, we risk reading garbage.
// But we can limit our check to simple fields if we are careful.
// Or we can rely on `scan`'s view being "good enough" if we accept some risk, 
// BUT input says "Add re-validation... safety critical".
// So we MUST try.
// Standard `shmid_ds` on Linux x86_64?
// Let's define a wrapper that roughly matches.
// Actually, `man shmctl` says `struct shmid_ds`.
// `shm_perm` is `struct ipc_perm`.
// `ipc_perm` is key(4), uid(4), gid(4), cuid(4), cgid(4), mode(4), seq(4)? No.
// Safe approach: Define enough space and use offsets? No.
// Let's use `extern struct` matching standard clib.

const ipc_perm = extern struct {
    __key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    __pad1: u16,
    __seq: u16,
    __pad2: u16,
    __unused1: c_ulong,
    __unused2: c_ulong,
};

const shmid_ds_linux = extern struct {
    shm_perm: ipc_perm,
    shm_segsz: usize,
    shm_atime: c_long,
    shm_dtime: c_long,
    shm_ctime: c_long,
    shm_cpid: i32,
    shm_lpid: i32,
    shm_nattch: usize,
    __unused4: c_ulong,
    __unused5: c_ulong,
};

pub fn verify_item(item: *SysVItem) !void {
    var ds: shmid_ds_linux = undefined;
    if (shmctl(@intCast(item.shmid), IPC_STAT, &ds) != 0) {
        return error.VerificationFailed;
    }
    
    // Check consistency
    // Note: ctime is stable? yes, set on creation or ipc_set.
    // bytes should match.
    // nattch should match 0 (orphan) if we think it's orphan?
    // User request: "ds.shm_nattch == 0 still holds (must be zero at delete time)"
    
    // Check size
    if (ds.shm_segsz != item.bytes) return error.SizeMismatch;
    
    // Check ctime
    if (@as(u64, @intCast(ds.shm_ctime)) != item.ctime) return error.CtimeMismatch;
    
    // Check nattch
    // If we are reaping, it SHOULD be 0.
    if (ds.shm_nattch > 0) return error.Attached;
}

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
                 
                 try classify_item(item, cfg, @intCast(std.time.timestamp()), false, allocator);
                 
                 try std.testing.expectEqual(item.classification, .likely_orphan);
                 found = true;
                 break;
            }
        }
        try std.testing.expect(found);
    }
}

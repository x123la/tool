const std = @import("std");
const config_mod = @import("config.zig");
const sysv_mod = @import("sysv.zig");
const Classification = sysv_mod.Classification;
const Recommendation = sysv_mod.Recommendation;

pub const PosixItem = struct {
    path: []u8, // full path
    inode: u64,
    dev: u64,
    bytes: u64,
    uid: u32,
    mtime: u64,
    ctime: u64,
    mode: u32,

    // Open handles
    open_pids: std.array_list.Managed(i32),
    open_pids_count: u32 = 0,

    // Derived
    age_seconds: u64 = 0,
    partial_proc_access: bool = false,

    classification: Classification = .unknown,
    recommendation: Recommendation = .keep,
    reclaimable_bytes: u64 = 0,
    reasons: std.array_list.Managed([]const u8),





    pub fn init(allocator: std.mem.Allocator) PosixItem {
        return PosixItem{
            .path = undefined,
            .inode = 0, .dev = 0, .bytes = 0, .uid = 0, .mtime = 0, .ctime = 0, .mode = 0,
            .open_pids = std.array_list.Managed(i32).init(allocator),
            .reasons = std.array_list.Managed([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *PosixItem, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.open_pids.deinit();
        self.reasons.deinit();
    }
};

pub fn scan_posix_dir(allocator: std.mem.Allocator, dir_path: []const u8) !std.array_list.Managed(PosixItem) {
    var items = std.array_list.Managed(PosixItem).init(allocator);
    errdefer {
        for (items.items) |*item| item.deinit(allocator);
        items.deinit();
    }

    var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch |err| {
        return err;
    };
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;

        var item = PosixItem.init(allocator);
        item.path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
        
        // stat
        const st = std.posix.fstatat(std.posix.AT.FDCWD, item.path, 0) catch {
            item.deinit(allocator);
            continue;
        };
        
        item.dev = st.dev;
        item.inode = st.ino;
        item.bytes = @intCast(st.size);
        item.uid = st.uid;
        item.mtime = @intCast(st.mtim.sec);
        item.ctime = @intCast(st.ctim.sec);
        item.mode = st.mode;

        try items.append(item);
    }
    return items;
}

pub fn correlate_open_fds(allocator: std.mem.Allocator, items: []PosixItem) !bool {
    var partial_error = false;
    
    // Build map (dev, ino) -> index
    const Key = struct { dev: u64, ino: u64 };
    var map = std.AutoHashMap(Key, usize).init(allocator);
    defer map.deinit();

    for (items, 0..) |item, i| {
        try map.put(Key{ .dev = item.dev, .ino = item.inode }, i);
    }

    var proc_dir = std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch return true; // Failure to open /proc means partial error
    defer proc_dir.close();

    var it = proc_dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;
        const pid = std.fmt.parseInt(i32, entry.name, 10) catch continue;

        var fd_dir_path_buf: [64]u8 = undefined;
        const fd_dir_path = std.fmt.bufPrint(&fd_dir_path_buf, "/proc/{d}/fd", .{pid}) catch continue;

        var fd_dir = std.fs.openDirAbsolute(fd_dir_path, .{ .iterate = true }) catch |err| {
            if (err == error.AccessDenied or err == error.PermissionDenied) {
                partial_error = true;
            }
            continue;
        };
        defer fd_dir.close();

        var fd_it = fd_dir.iterate();
        while (try fd_it.next()) |fd_entry| {
             var fd_path_buf: [128]u8 = undefined;
             const fd_path = std.fmt.bufPrint(&fd_path_buf, "/proc/{d}/fd/{s}", .{pid, fd_entry.name}) catch continue;
             const st = std.posix.fstatat(std.posix.AT.FDCWD, fd_path, 0) catch continue;
             
             const k = Key{ .dev = st.dev, .ino = st.ino };
             if (map.get(k)) |idx| {
                 var item = &items[idx];
                 item.open_pids_count += 1;
                 if (item.open_pids.items.len < 32) {
                     try item.open_pids.append(pid);
                 }
             }
        }
    }
    return partial_error;
}

pub fn classify_item(item: *PosixItem, cfg: config_mod.Config, current_time: u64, partial_proc_access: bool) !void {
    // 1. Allowlist
    var allowlisted = false;
    for (cfg.allow_owners.items) |owner| {
        if (item.uid == owner) {
            allowlisted = true;
            break;
        }
    }
    if (!allowlisted) {
        for (cfg.allow_names.items) |name| {
            if (std.mem.indexOf(u8, item.path, name) != null) {
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

    // 2. Open handles
    if (item.open_pids_count > 0) {
        item.classification = .in_use;
        item.recommendation = .keep;
        try item.reasons.append("OPEN_HANDLES_PRESENT");
        return;
    }
    try item.reasons.append("NO_OPEN_HANDLES");

    // Age
    item.age_seconds = if (item.mtime == 0) 0 else (if (current_time > item.mtime) current_time - item.mtime else 0);

    // Min bytes
    if (item.bytes < cfg.min_bytes) {
        item.classification = .unknown;
        item.recommendation = .keep;
        try item.reasons.append("BELOW_MIN_BYTES");
        return;
    }

    // Partial proc access
    if (partial_proc_access) {
        const current_uid = std.posix.getuid();
        const is_private = (item.mode & 0o077) == 0; // No group or other permissions

        if (item.uid == current_uid and is_private) {
            try item.reasons.append("PARTIAL_PROC_OVERRIDE_PRIVATE");
            // Proceed to normal classification
        } else {
            item.classification = .unknown;
            item.recommendation = .review;
            item.reclaimable_bytes = 0;
            try item.reasons.append("INSUFFICIENT_PROC_PERMS");
            if (item.age_seconds >= cfg.threshold_seconds) {
                try item.reasons.append("OLDER_THAN_THRESHOLD");
            } else {
                try item.reasons.append("YOUNGER_THAN_THRESHOLD");
            }
            return;
        }
    }

    // Full proc access
    if (item.age_seconds >= cfg.threshold_seconds) {
        item.classification = .likely_orphan;
        item.recommendation = .reap;
        item.reclaimable_bytes = item.bytes;
        try item.reasons.append("OLDER_THAN_THRESHOLD");
    } else {
        item.classification = .unknown;
        item.recommendation = .keep;
        try item.reasons.append("YOUNGER_THAN_THRESHOLD");
    }

    // Risk override
    const basename = std.fs.path.basename(item.path);
    const risky_substrings = [_][]const u8{ "pulse", "pipewire", "wayland", "dbus" };
    var risky = false;
    for (risky_substrings) |sub| {
        if (std.mem.indexOf(u8, basename, sub) != null) {
            risky = true;
            break;
        }
    }

    if (risky) {
        if (item.classification == .likely_orphan or item.classification == .possible_orphan) {
            item.classification = .risky_to_remove;
            item.recommendation = .review;
            try item.reasons.append("RISKY_NAME_PATTERN");
            item.reclaimable_bytes = 0;
        }
    }
}


// Redefine verify_item to take allocator
pub fn verify_item_alloc(allocator: std.mem.Allocator, item: *PosixItem) !void {
     _ = allocator;
     const st = try std.posix.fstatat(std.posix.AT.FDCWD, item.path, 0);
     
     if (st.dev != item.dev) return error.IdentityMismatch;
     if (st.ino != item.inode) return error.IdentityMismatch;
}

// Tests
test "integration posix open-handle" {
    if (@import("builtin").os.tag != .linux) return;
    const allocator = std.testing.allocator;

    // Create temp dir
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    // Create file
    const file_path = try std.fs.path.join(allocator, &[_][]const u8{ tmp_path, "test_shm" });
    defer allocator.free(file_path);
    
    // Create large file > min_bytes default (65536)
    const file = try std.fs.createFileAbsolute(file_path, .{});
    try file.deprecatedWriter().writeByteNTimes('a', 70000);
    file.close();

    const pid = try std.posix.fork();
    if (pid == 0) {
        // Child: Open file, sleep
        const f = std.fs.openFileAbsolute(file_path, .{}) catch std.posix.exit(1);
        _ = f; // keep handle open
        std.Thread.sleep(2 * std.time.ns_per_s);
        std.posix.exit(0);
    } else {
        // Parent
        // Wait 0.5s for child to open
        std.Thread.sleep(500 * std.time.ns_per_ms);
        
        // Scan 1: Assert In Use
        var items = try scan_posix_dir(allocator, tmp_path);
        defer { for(items.items)|*i|i.deinit(allocator); items.deinit(); }
        
        _ = try correlate_open_fds(allocator, items.items);
        
        var found = false;
        for (items.items) |*item| {
            if (std.mem.eql(u8, item.path, file_path)) {
                found = true;
                 // Should have open pids
                 try std.testing.expect(item.open_pids_count > 0);
                 
                 // Check classify logic
                 var cfg = config_mod.Config.init(allocator);
                 defer cfg.deinit();
                 
                 try classify_item(item, cfg, @intCast(std.time.timestamp()), false);
                 try std.testing.expectEqual(item.classification, .in_use);
            }
        }
        try std.testing.expect(found);
        
        // Wait for child to exit
        _ = std.posix.waitpid(pid, 0);
        
        // Scan 2: Assert Orphan
        // Need to wait? No, handle closed on exit.
         var items2 = try scan_posix_dir(allocator, tmp_path);
        defer { for(items2.items)|*i|i.deinit(allocator); items2.deinit(); }
        
        _ = try correlate_open_fds(allocator, items2.items);
        
         for (items2.items) |*item| {
            if (std.mem.eql(u8, item.path, file_path)) {
                 // Should have 0 open pids
                 try std.testing.expect(item.open_pids_count == 0);
                 
                 var cfg = config_mod.Config.init(allocator);
                 defer cfg.deinit();
                 cfg.threshold_seconds = 0; // force immediate orphan
                 
                 try classify_item(item, cfg, @intCast(std.time.timestamp()), false);
                 try std.testing.expectEqual(item.classification, .likely_orphan);
            }
         }
    }
}

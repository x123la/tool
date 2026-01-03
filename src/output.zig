const std = @import("std");
const sysv_mod = @import("sysv.zig");
const posix_mod = @import("posix.zig");

pub const Item = union(enum) {
    sysv: *sysv_mod.SysVItem,
    posix: *posix_mod.PosixItem,
};

pub const Summary = struct {
    sysv_total_bytes: u64 = 0,
    posix_total_bytes: u64 = 0,
    likely_orphan_bytes: u64 = 0,
    likely_orphan_count: u64 = 0,
    partial_proc_access: bool = false,
};

// ANSI colors
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RESET = "\x1b[0m";

pub fn get_color(cls: sysv_mod.Classification) []const u8 {
    return switch (cls) {
        .likely_orphan => GREEN,
        .possible_orphan => YELLOW,
        .risky_to_remove => RED,
        else => "",
    };
}

pub fn classification_str(cls: sysv_mod.Classification) []const u8 {
    return switch (cls) {
        .allowlisted => "allowlisted",
        .in_use => "in_use",
        .likely_orphan => "likely_orphan",
        .possible_orphan => "possible_orphan",
        .unknown => "unknown",
        .risky_to_remove => "risky_to_remove",
    };
}

pub fn recommendation_str(rec: sysv_mod.Recommendation) []const u8 {
    return switch (rec) {
        .keep => "keep",
        .review => "review",
        .reap => "reap",
    };
}

pub fn print_table(items: []const Item, summary: Summary, no_color: bool) !void {
    const stdout_file = std.fs.File.stdout();
    var stdout = stdout_file.deprecatedWriter();

    // Sort items: recommendation order (reap, review, keep), then bytes desc
    // We can't sort the input slice in place easily if it's const or mixed pointers.
    // Let's create a sorting index.
    const SortItem = struct {
        idx: usize,
        ptr: Item,
        rec_score: u8, // 0=reap, 1=review, 2=keep
        bytes: u64,
    };

    var sorted = try std.array_list.Managed(SortItem).initCapacity(std.heap.page_allocator, items.len);
    defer sorted.deinit();

    for (items, 0..) |item, i| {
        const rec: sysv_mod.Recommendation = switch (item) {
            .sysv => |s| s.recommendation,
            .posix => |p| p.recommendation,
        };
        const bytes: u64 = switch (item) {
            .sysv => |s| s.bytes,
            .posix => |p| p.bytes,
        };
        const score: u8 = switch (rec) {
            .reap => 0,
            .review => 1,
            .keep => 2,
        };
        sorted.appendAssumeCapacity(.{ .idx = i, .ptr = item, .rec_score = score, .bytes = bytes });
    }

    std.sort.block(SortItem, sorted.items, {}, struct {
        fn lessThan(_: void, a: SortItem, b: SortItem) bool {
            if (a.rec_score != b.rec_score) return a.rec_score < b.rec_score;
            return a.bytes > b.bytes;
        }
    }.lessThan);

    // Header
    try stdout.print("TYPE   ID                                                           SIZE_BYTES  AGE_SECONDS  IN_USE  OWNER_UID  CLASSIFICATION       RECOMMENDATION\n", .{});

    for (sorted.items) |si| {
        switch (si.ptr) {
            .sysv => |s| {
                const color = if (no_color) "" else get_color(s.classification);
                const rst = if (no_color) "" else RESET;
                const cls_s = classification_str(s.classification);
                const rec_s = recommendation_str(s.recommendation);
                // ID is shmid (i32)
                // We need fixed width padding
                // TYPE (6) ID (60) SIZE (10) AGE (11) IN_USE (6) UID (9) CLASS (19) REC (14)
                // Using somewhat flexible formatting
                try stdout.print("sysv   {d:<60} {d:>10}  {d:>11}  {d:>6}  {d:>9}  {s}{s:<19}{s}  {s}\n", 
                    .{s.shmid, s.bytes, s.age_seconds, s.nattch, s.uid, color, cls_s, rst, rec_s});
            },
            .posix => |p| {
                const color = if (no_color) "" else get_color(p.classification);
                const rst = if (no_color) "" else RESET;
                const cls_s = classification_str(p.classification);
                const rec_s = recommendation_str(p.recommendation);
                // ID is basename of file (not full path)
                const base = std.fs.path.basename(p.path);
                // Truncate to 60 chars?
                var id_buf: [61]u8 = undefined;
                const len = @min(base.len, 60);
                @memcpy(id_buf[0..len], base[0..len]);
                if (len < 60) {
                    for (id_buf[len..60]) |*c| c.* = ' ';
                }
                id_buf[60] = 0; // if we print as string slice?
                const id_view = id_buf[0..len]; 
                
                try stdout.print("posix  {s:<60} {d:>10}  {d:>11}  {d:>6}  {d:>9}  {s}{s:<19}{s}  {s}\n", 
                    .{id_view, p.bytes, p.age_seconds, p.open_pids_count, p.uid, color, cls_s, rst, rec_s});
            }
        }
    }

    // Summary
    try stdout.print("\nSYSV_TOTAL_BYTES={d}\n", .{summary.sysv_total_bytes});
    try stdout.print("POSIX_TOTAL_BYTES={d}\n", .{summary.posix_total_bytes});
    try stdout.print("LIKELY_ORPHAN_BYTES={d}\n", .{summary.likely_orphan_bytes});
    try stdout.print("LIKELY_ORPHAN_COUNT={d}\n", .{summary.likely_orphan_count});
    try stdout.print("PARTIAL_PROC_ACCESS={}\n", .{summary.partial_proc_access});
    
    // try stdout.flush(); // deprecatedWriter is unbuffered or doesn't expose flush
}


pub fn print_json(items: []const Item, summary: Summary, cfg: anytype, generated_at: u64) !void {
    const stdout_file = std.fs.File.stdout();
    var writer = stdout_file.deprecatedWriter();

    const JsonItem = struct {
        type: []const u8,
        // SysV fields
        shmid: ?i32 = null,
        key: ?[]const u8 = null,
        nattch: ?u32 = null,
        perms: ?u32 = null,
        cpid: ?i32 = null,
        lpid: ?i32 = null,
        ctime: ?u64 = null,
        creator_alive: ?bool = null,
        creator_pid_reused: ?bool = null,
        last_alive: ?bool = null,
        last_pid_reused: ?bool = null,
        
        // Posix fields
        path: ?[]const u8 = null,
        inode: ?u64 = null,
        mtime: ?u64 = null,
        open_pids_count: ?u32 = null,
        open_pids: ?[]const i32 = null,

        // Common
        bytes: u64,
        uid: u32,
        age_seconds: u64,
        classification: []const u8,
        recommendation: []const u8,
        reclaimable_bytes: u64,
        reasons: []const []const u8,
    };

    var json_items = std.array_list.Managed(JsonItem).init(std.heap.page_allocator);
    defer json_items.deinit();

    // Buffer for hex keys
    var key_bufs: [128][32]u8 = undefined; // Cycle buffer for hex strings
    var key_buf_idx: usize = 0;

    for (items) |item| {
        switch (item) {
            .sysv => |s| {
                // Format key hex
                const buf = &key_bufs[key_buf_idx % 128];
                key_buf_idx += 1;
                const k_str = try std.fmt.bufPrint(buf, "0x{x}", .{s.key});

                try json_items.append(.{
                    .type = "sysv",
                    .shmid = s.shmid,
                    .key = k_str,
                    .nattch = s.nattch,
                    .perms = s.perms,
                    .cpid = s.cpid,
                    .lpid = s.lpid,
                    .ctime = s.ctime,
                    .creator_alive = s.creator_alive,
                    .creator_pid_reused = s.creator_pid_reused,
                    .last_alive = s.last_alive,
                    .last_pid_reused = s.last_pid_reused,
                    .bytes = s.bytes,
                    .uid = s.uid,
                    .age_seconds = s.age_seconds,
                    .classification = classification_str(s.classification),
                    .recommendation = recommendation_str(s.recommendation),
                    .reclaimable_bytes = s.reclaimable_bytes,
                    .reasons = s.reasons.items,
                });
            },
            .posix => |p| {
                try json_items.append(.{
                    .type = "posix",
                    .path = p.path,
                    .inode = p.inode,
                    .mtime = p.mtime,
                    .open_pids_count = p.open_pids_count,
                    .open_pids = p.open_pids.items,
                    .bytes = p.bytes,
                    .uid = p.uid,
                    .age_seconds = p.age_seconds,
                    .classification = classification_str(p.classification),
                    .recommendation = recommendation_str(p.recommendation),
                    .reclaimable_bytes = p.reclaimable_bytes,
                    .reasons = p.reasons.items,
                });
            }
        }
    }

    const JsonOut = struct {
        generated_at: u64,
        threshold_seconds: u64,
        min_bytes: u64,
        posix_dir: []const u8,
        partial_proc_access: bool,
        items: []const JsonItem,
        summary: Summary,
    };

    const out_obj = JsonOut{
        .generated_at = generated_at,
        .threshold_seconds = cfg.threshold_seconds,
        .min_bytes = cfg.min_bytes,
        .posix_dir = cfg.posix_dir,
        .partial_proc_access = summary.partial_proc_access,
        .items = json_items.items,
        .summary = summary,
    };

    try writer.print("{f}", .{std.json.fmt(out_obj, .{})});
}

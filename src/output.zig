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

fn get_color(cls: sysv_mod.Classification) []const u8 {
    return switch (cls) {
        .likely_orphan => GREEN,
        .possible_orphan => YELLOW,
        .risky_to_remove => RED,
        else => "",
    };
}

fn classification_str(cls: sysv_mod.Classification) []const u8 {
    return switch (cls) {
        .allowlisted => "allowlisted",
        .in_use => "in_use",
        .likely_orphan => "likely_orphan",
        .possible_orphan => "possible_orphan",
        .unknown => "unknown",
        .risky_to_remove => "risky_to_remove",
    };
}

fn recommendation_str(rec: sysv_mod.Recommendation) []const u8 {
    return switch (rec) {
        .keep => "keep",
        .review => "review",
        .reap => "reap",
    };
}

pub fn print_table(items: []const Item, summary: Summary, no_color: bool) !void {
    const stdout = std.io.getStdOut().writer();

    // Sort items: recommendation order (reap, review, keep), then bytes desc
    // We can't sort the input slice in place easily if it's const or mixed pointers.
    // Let's create a sorting index.
    const SortItem = struct {
        idx: usize,
        ptr: Item,
        rec_score: u8, // 0=reap, 1=review, 2=keep
        bytes: u64,
    };

    var sorted = try std.ArrayList(SortItem).initCapacity(std.heap.page_allocator, items.len);
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

    try stdout.print("\nSYSV_TOTAL_BYTES={d}\n", .{summary.sysv_total_bytes});
    try stdout.print("POSIX_TOTAL_BYTES={d}\n", .{summary.posix_total_bytes});
    try stdout.print("LIKELY_ORPHAN_BYTES={d}\n", .{summary.likely_orphan_bytes});
    try stdout.print("LIKELY_ORPHAN_COUNT={d}\n", .{summary.likely_orphan_count});
    try stdout.print("PARTIAL_PROC_ACCESS={}\n", .{summary.partial_proc_access});
}

pub fn print_json(items: []const Item, summary: Summary, cfg: anytype, generated_at: u64) !void {
    const stdout = std.io.getStdOut().writer();
    // Use std.json
    // But std.json requires a struct to serialize usually or usage of writeValue.
    // We'll construct a wrapper struct or use write function manually.
    // Manual writing is safer for exact schema control.
    
    // Actually, `std.json.stringify` is powerful.
    
    // We can create a wrapper struct that holds everything?
    // But items is a union array.
    
    var ws = std.json.writeStream(stdout, .{});
    try ws.beginObject();
    try ws.objectField("generated_at"); try ws.write(generated_at);
    try ws.objectField("threshold_seconds"); try ws.write(cfg.threshold_seconds);
    try ws.objectField("min_bytes"); try ws.write(cfg.min_bytes);
    try ws.objectField("posix_dir"); try ws.write(cfg.posix_dir);
    try ws.objectField("partial_proc_access"); try ws.write(summary.partial_proc_access);
    
    try ws.objectField("items");
    try ws.beginArray();
    for (items) |item| {
        switch (item) {
            .sysv => |s| {
                try ws.beginObject();
                try ws.objectField("type"); try ws.write("sysv");
                try ws.objectField("shmid"); try ws.write(s.shmid);
                
                // key hex string
                var buf: [32]u8 = undefined;
                const k = std.fmt.bufPrint(&buf, "0x{x}", .{s.key}) catch "0x0";
                try ws.objectField("key"); try ws.write(k);
                
                try ws.objectField("bytes"); try ws.write(s.bytes);
                try ws.objectField("nattch"); try ws.write(s.nattch);
                try ws.objectField("uid"); try ws.write(s.uid);
                try ws.objectField("perms"); try ws.write(s.perms);
                try ws.objectField("cpid"); try ws.write(s.cpid);
                try ws.objectField("lpid"); try ws.write(s.lpid);
                try ws.objectField("ctime"); try ws.write(s.ctime);
                try ws.objectField("age_seconds"); try ws.write(s.age_seconds);
                try ws.objectField("creator_alive"); try ws.write(s.creator_alive);
                try ws.objectField("creator_pid_reused"); try ws.write(s.creator_pid_reused);
                try ws.objectField("last_alive"); try ws.write(s.last_alive);
                try ws.objectField("last_pid_reused"); try ws.write(s.last_pid_reused);
                try ws.objectField("classification"); try ws.write(classification_str(s.classification));
                try ws.objectField("recommendation"); try ws.write(recommendation_str(s.recommendation));
                try ws.objectField("reclaimable_bytes"); try ws.write(s.reclaimable_bytes);
                
                try ws.objectField("reasons");
                try ws.beginArray();
                for (s.reasons.items) |r| try ws.write(r);
                try ws.endArray();
                
                try ws.endObject();
            },
            .posix => |p| {
                try ws.beginObject();
                try ws.objectField("type"); try ws.write("posix");
                try ws.objectField("path"); try ws.write(p.path);
                try ws.objectField("inode"); try ws.write(p.inode);
                try ws.objectField("bytes"); try ws.write(p.bytes);
                try ws.objectField("uid"); try ws.write(p.uid);
                try ws.objectField("mtime"); try ws.write(p.mtime);
                try ws.objectField("age_seconds"); try ws.write(p.age_seconds);
                try ws.objectField("open_pids_count"); try ws.write(p.open_pids_count);
                
                try ws.objectField("open_pids");
                try ws.beginArray();
                for (p.open_pids.items) |pid| try ws.write(pid);
                try ws.endArray();
                
                try ws.objectField("classification"); try ws.write(classification_str(p.classification));
                try ws.objectField("recommendation"); try ws.write(recommendation_str(p.recommendation));
                try ws.objectField("reclaimable_bytes"); try ws.write(p.reclaimable_bytes);
                
                try ws.objectField("reasons");
                try ws.beginArray();
                for (p.reasons.items) |r| try ws.write(r);
                try ws.endArray();
                
                try ws.endObject();
            }
        }
    }
    try ws.endArray();
    
    try ws.objectField("summary");
    try ws.beginObject();
    try ws.objectField("sysv_total_bytes"); try ws.write(summary.sysv_total_bytes);
    try ws.objectField("posix_total_bytes"); try ws.write(summary.posix_total_bytes);
    try ws.objectField("likely_orphan_bytes"); try ws.write(summary.likely_orphan_bytes);
    try ws.objectField("likely_orphan_count"); try ws.write(summary.likely_orphan_count);
    try ws.endObject();
    
    try ws.endObject();
    // No trailing newline in JSON? "One JSON object to stdout. No trailing text."
    // std.json writer doesn't add newline.
}

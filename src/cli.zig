const std = @import("std");
const config_mod = @import("config.zig");
const sysv_mod = @import("sysv.zig");
const posix_mod = @import("posix.zig");
const time_mod = @import("time.zig");
const proc_mod = @import("proc.zig");
const output_mod = @import("output.zig");

const c_shm = @cImport({
    @cInclude("sys/ipc.h");
    @cInclude("sys/shm.h");
});

extern "c" fn unlink(path: [*:0]const u8) c_int;

pub fn run(allocator: std.mem.Allocator) !u8 {
    var cfg = try config_mod.parse_args(allocator);
    defer cfg.deinit(); 
    
    const sys_time = try time_mod.get_system_time();
    const now = time_mod.get_current_timestamp();
    
    switch (cfg.mode) {
        .scan => return run_scan(allocator, cfg, sys_time, now),
        .explain => return run_explain(allocator, cfg, sys_time, now),
        .reap => return run_reap(allocator, cfg, sys_time, now),
    }
}

fn run_scan(allocator: std.mem.Allocator, cfg: config_mod.Config, sys_time: time_mod.SystemTime, now: u64) !u8 {
    var sysv_items: std.array_list.Managed(sysv_mod.SysVItem) = undefined;
    if (cfg.target_type == .sysv or cfg.target_type == .both) {
        sysv_items = try sysv_mod.parse_sysv_shm(allocator, "/proc/sysvipc/shm");
    } else {
        sysv_items = std.array_list.Managed(sysv_mod.SysVItem).init(allocator);
    }
    defer {
        for (sysv_items.items) |*i| i.deinit();
        sysv_items.deinit();
    }
    
    var posix_items: std.array_list.Managed(posix_mod.PosixItem) = undefined;
    var partial_proc_access_posix = false;
    
    if (cfg.target_type == .posix or cfg.target_type == .both) {
        posix_items = try posix_mod.scan_posix_dir(allocator, cfg.posix_dir);
        partial_proc_access_posix = try posix_mod.correlate_open_fds(allocator, posix_items.items);
    } else {
        posix_items = std.array_list.Managed(posix_mod.PosixItem).init(allocator);
    }
    defer {
        for (posix_items.items) |*i| i.deinit(allocator);
        posix_items.deinit();
    }
    
    var items = std.array_list.Managed(output_mod.Item).init(allocator);
    defer items.deinit(); // pointers only, safe
    
    var partial_proc_access_sysv = false;

    // Process SysV
    for (sysv_items.items) |*item| {
        // Liveness
        if (item.cpid > 0) {
            const start = proc_mod.get_pid_starttime(allocator, item.cpid) catch |err| switch (err) {
                error.PidNotFound => @as(u64, 0),
                else => blk: {
                    partial_proc_access_sysv = true;
                    break :blk @as(u64, 0);
                },
            };
            if (start != 0) {
                item.creator_alive = true;
                if (item.ctime != 0) {
                     const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                     if (start_epoch > item.ctime + 2) {
                         item.creator_pid_reused = true;
                     }
                }
            }
        }
        if (item.lpid > 0) {
            const start = proc_mod.get_pid_starttime(allocator, item.lpid) catch |err| switch (err) {
                error.PidNotFound => @as(u64, 0),
                else => blk: {
                    partial_proc_access_sysv = true;
                    break :blk @as(u64, 0);
                },
            };
             if (start != 0) {
                item.last_alive = true;
                if (item.ctime != 0) {
                     const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                     if (start_epoch > item.ctime + 2) {
                         item.last_pid_reused = true;
                     }
                }
            }
        }
        
        try sysv_mod.classify_item(item, cfg, now, partial_proc_access_sysv, allocator);
        try items.append(output_mod.Item{ .sysv = item });
    }

    // Process POSIX
    for (posix_items.items) |*item| {
        try posix_mod.classify_item(item, cfg, now, partial_proc_access_posix);
        try items.append(output_mod.Item{ .posix = item });
    }

    // Summary
    var summary = output_mod.Summary{};
    summary.partial_proc_access = (partial_proc_access_sysv or partial_proc_access_posix);
    
    var likely_orphan_exists = false;

    for (items.items) |it| {
        switch (it) {
            .sysv => |s| {
                summary.sysv_total_bytes += s.bytes;
                if (s.classification == .likely_orphan) {
                    summary.likely_orphan_bytes += s.bytes;
                    summary.likely_orphan_count += 1;
                    likely_orphan_exists = true;
                }
            },
            .posix => |p| {
                summary.posix_total_bytes += p.bytes;
                if (p.classification == .likely_orphan) {
                    summary.likely_orphan_bytes += p.bytes;
                    summary.likely_orphan_count += 1;
                    likely_orphan_exists = true;
                }
            }
        }
    }

    if (cfg.json) {
        try output_mod.print_json(items.items, summary, cfg, now);
    } else {
        try output_mod.print_table(items.items, summary, cfg.no_color);
    }

    if (summary.partial_proc_access) return 2;
    if (likely_orphan_exists) return 1;
    return 0;
}

fn run_explain(allocator: std.mem.Allocator, cfg: config_mod.Config, sys_time: time_mod.SystemTime, now: u64) !u8 {
    var sysv_items: std.array_list.Managed(sysv_mod.SysVItem) = undefined;
    if (cfg.target_type == .sysv or cfg.target_type == .both) {
        sysv_items = try sysv_mod.parse_sysv_shm(allocator, "/proc/sysvipc/shm");
    } else {
        sysv_items = std.array_list.Managed(sysv_mod.SysVItem).init(allocator);
    }
    defer {
        for (sysv_items.items) |*i| i.deinit();
        sysv_items.deinit();
    }
    
    var posix_items: std.array_list.Managed(posix_mod.PosixItem) = undefined;
    var partial_proc_access_posix = false;
    if (cfg.target_type == .posix or cfg.target_type == .both) {
        posix_items = try posix_mod.scan_posix_dir(allocator, cfg.posix_dir);
        partial_proc_access_posix = try posix_mod.correlate_open_fds(allocator, posix_items.items);
    } else {
        posix_items = std.array_list.Managed(posix_mod.PosixItem).init(allocator);
    }
    defer {
        for (posix_items.items) |*i| i.deinit(allocator);
        posix_items.deinit();
    }
    
    var partial_proc_access_sysv = false;
    
    var found_item: ?output_mod.Item = null;
    var target_shmid: ?i32 = null;
    var target_path: ?[]const u8 = null;
    
    const id = cfg.explain_id;
    if (std.mem.startsWith(u8, id, "sysv:")) {
        target_shmid = std.fmt.parseInt(i32, id[5..], 10) catch return 64;
    } else if (std.mem.startsWith(u8, id, "posix:")) {
        target_path = id[6..];
    } else {
        if (std.fmt.parseInt(i32, id, 10)) |v| {
            target_shmid = v;
        } else |_| {
            target_path = id;
        }
    }

    if (target_shmid) |tid| {
        for (sysv_items.items) |*item| {
            if (item.shmid == tid) {
                if (item.cpid > 0) {
                     const start = proc_mod.get_pid_starttime(allocator, item.cpid) catch |err| switch (err) {
                        error.PidNotFound => @as(u64, 0),
                        else => blk: {
                            partial_proc_access_sysv = true;
                            break :blk @as(u64, 0);
                        },
                     };
                     if (start != 0) {
                         item.creator_alive = true;
                         if (item.ctime != 0) {
                             const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                             if (start_epoch > item.ctime + 2) item.creator_pid_reused = true;
                         }
                     }
                }
                if (item.lpid > 0) {
                     const start = proc_mod.get_pid_starttime(allocator, item.lpid) catch |err| switch (err) {
                        error.PidNotFound => @as(u64, 0),
                        else => blk: {
                            partial_proc_access_sysv = true;
                            break :blk @as(u64, 0);
                        },
                     };
                     if (start != 0) {
                         item.last_alive = true;
                         if (item.ctime != 0) {
                             const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                             if (start_epoch > item.ctime + 2) item.last_pid_reused = true;
                         }
                     }
                }
                try sysv_mod.classify_item(item, cfg, now, partial_proc_access_sysv, allocator);
                found_item = output_mod.Item{ .sysv = item };
                break;
            }
        }
    } else if (target_path) |tpath| {
         for (posix_items.items) |*item| {
             const base = std.fs.path.basename(item.path);
             const p_base = std.fs.path.basename(tpath);
             if (std.mem.eql(u8, item.path, tpath) or std.mem.eql(u8, base, p_base)) {
                 try posix_mod.classify_item(item, cfg, now, partial_proc_access_posix);
                 found_item = output_mod.Item{ .posix = item };
                 break;
             }
         }
    }

    if (cfg.json) {
        const stdout_file = std.fs.File.stdout();
        var writer = stdout_file.deprecatedWriter();

        // Schema for Explain
        const JsonExplain = struct {
            found: bool,
            sysv: ?struct {
                shmid: i32,
                bytes: u64,
                classification: []const u8,
                recommendation: []const u8,
                reasons: []const []const u8,
            } = null,
            posix: ?struct {
                path: []const u8,
                bytes: u64,
                classification: []const u8,
                recommendation: []const u8,
                reasons: []const []const u8,
            } = null,
        };

        var out_obj = JsonExplain{ .found = (found_item != null) };

        if (found_item) |it| {
            switch (it) {
                .sysv => |s| {
                    out_obj.sysv = .{
                        .shmid = s.shmid,
                        .bytes = s.bytes,
                        .classification = output_mod.classification_str(s.classification), // output_mod made pub? Check if it is public.
                        // Wait, output_mod functions were private? I need to check if classification_str is pub.
                        // If not, I should duplicate logic or make it pub. 
                        // Assuming I will make them pub in output.zig or they are already usable if I import correctly.
                        // Actually, they are private in output.zig (fn classification_str).
                        // I will make them pub in a separate edit or duplicate strings here for safety now.
                        .recommendation = @tagName(s.recommendation),
                        .reasons = s.reasons.items,
                    };
                },
                .posix => |p| {
                     out_obj.posix = .{
                         .path = p.path,
                         .bytes = p.bytes,
                         .classification = @tagName(p.classification),
                         .recommendation = @tagName(p.recommendation),
                         .reasons = p.reasons.items,
                     };
                }
            }
        }
        try writer.print("{f}", .{std.json.fmt(out_obj, .{})});

    } else {
        const stdout_file = std.fs.File.stdout();
        var writer = stdout_file.deprecatedWriter();
        if (found_item) |it| {
            switch (it) {
                .sysv => |s| {
                    try writer.print("EXPLAIN TYPE=sysv ID={d}\n", .{s.shmid});
                    try writer.print("  key: 0x{x:0>8}\n", .{s.key});
                    try writer.print("  bytes: {d}\n  age: {d}s\n  nattch: {d}\n", .{s.bytes, s.age_seconds, s.nattch});
                    try writer.print("  uid: {d}\n  perms: 0o{o}\n", .{s.uid, s.perms});
                    try writer.print("  creator_pid: {d} (alive: {}, reused: {})\n", .{s.cpid, s.creator_alive, s.creator_pid_reused});
                    try writer.print("  last_pid: {d} (alive: {}, reused: {})\n", .{s.lpid, s.last_alive, s.last_pid_reused});
                    try writer.print("CLASSIFICATION: {s}\n", .{@tagName(s.classification)});
                    for (s.reasons.items) |r| try writer.print("- {s}\n", .{r});
                },
                .posix => |p| {
                    try writer.print("EXPLAIN TYPE=posix ID={s}\n", .{p.path});
                    try writer.print("  bytes: {d}\n  age: {d}s\n", .{p.bytes, p.age_seconds});
                    try writer.print("  uid: {d}\n", .{p.uid});
                    try writer.print("  open_pids_count: {d}\n", .{p.open_pids_count});
                    if (p.open_pids_count > 0) {
                        try writer.print("  open_pids: ", .{});
                        for (p.open_pids.items, 0..) |pid, i| {
                            try writer.print("{d}{s}", .{pid, if (i < p.open_pids.items.len - 1) ", " else ""});
                        }
                        try writer.print("\n", .{});
                    }
                    try writer.print("CLASSIFICATION: {s}\n", .{@tagName(p.classification)});
                    for (p.reasons.items) |r| try writer.print("- {s}\n", .{r});
                }
            }
        } else {
            try writer.print("Item not found.\n", .{});
        }
    }

    if (partial_proc_access_sysv or partial_proc_access_posix) return 2;
    return 0;
}

fn run_reap(allocator: std.mem.Allocator, cfg: config_mod.Config, sys_time: time_mod.SystemTime, now: u64) !u8 {
    var sysv_items: std.array_list.Managed(sysv_mod.SysVItem) = undefined;
    if (cfg.target_type == .sysv or cfg.target_type == .both) {
        sysv_items = try sysv_mod.parse_sysv_shm(allocator, "/proc/sysvipc/shm");
    } else {
        sysv_items = std.array_list.Managed(sysv_mod.SysVItem).init(allocator);
    }
    defer {
        for (sysv_items.items) |*i| i.deinit();
        sysv_items.deinit();
    }

    var posix_items: std.array_list.Managed(posix_mod.PosixItem) = undefined;
    var partial_proc_access_posix = false;
    if (cfg.target_type == .posix or cfg.target_type == .both) {
        posix_items = try posix_mod.scan_posix_dir(allocator, cfg.posix_dir);
        partial_proc_access_posix = try posix_mod.correlate_open_fds(allocator, posix_items.items);
    } else {
        posix_items = std.array_list.Managed(posix_mod.PosixItem).init(allocator);
    }
    defer {
        for (posix_items.items) |*i| i.deinit(allocator);
        posix_items.deinit();
    }

    var partial_proc_access_sysv = false;
    var plan = std.array_list.Managed(output_mod.Item).init(allocator);
    defer plan.deinit();

    // Classification & Planning
    for (sysv_items.items) |*item| {
        if (item.cpid > 0) {
             const start = proc_mod.get_pid_starttime(allocator, item.cpid) catch |err| switch (err) {
                 error.PidNotFound => @as(u64, 0),
                 else => blk: {
                     partial_proc_access_sysv = true;
                     break :blk @as(u64, 0);
                 },
             };
             if (start != 0) {
                 item.creator_alive = true;
                 if (item.ctime != 0) {
                     const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                     if (start_epoch > item.ctime + 2) item.creator_pid_reused = true;
                 }
             }
        }
        if (item.lpid > 0) {
             const start = proc_mod.get_pid_starttime(allocator, item.lpid) catch |err| switch (err) {
                 error.PidNotFound => @as(u64, 0),
                 else => blk: {
                     partial_proc_access_sysv = true;
                     break :blk @as(u64, 0);
                 },
             };
             if (start != 0) {
                 item.last_alive = true;
                 if (item.ctime != 0) {
                     const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                     if (start_epoch > item.ctime + 2) item.last_pid_reused = true;
                 }
             }
        }
        
        try sysv_mod.classify_item(item, cfg, now, partial_proc_access_sysv, allocator);
        
        var eligible = false;
        if (item.recommendation == .reap and item.classification == .likely_orphan) eligible = true;
        if (cfg.force) {
            if (item.classification == .possible_orphan or item.classification == .risky_to_remove) eligible = true;
        }
        if (item.classification == .allowlisted or item.classification == .in_use) eligible = false;
        
        if (eligible) try plan.append(output_mod.Item{ .sysv = item });
    }

    for (posix_items.items) |*item| {
        try posix_mod.classify_item(item, cfg, now, partial_proc_access_posix);
        
        var eligible = false;
        if (item.recommendation == .reap and item.classification == .likely_orphan) eligible = true;
        if (cfg.force) {
            if (item.classification == .possible_orphan or item.classification == .risky_to_remove) eligible = true;
        }
        if (item.classification == .allowlisted or item.classification == .in_use) eligible = false;
        
        if (eligible) try plan.append(output_mod.Item{ .posix = item });
    }

    const dry_run = !cfg.apply;
    var planned_total_bytes: u64 = 0;
    for (plan.items) |it| {
        switch (it) {
            .sysv => |s| planned_total_bytes += s.bytes,
            .posix => |p| planned_total_bytes += p.bytes,
        }
    }
    
    // Results
    const Result = struct {
        kind: []const u8,
        id: ?i32,
        path: ?[]const u8,
        attempted: bool,
        deleted: bool,
        error_msg: ?[]const u8,
    };
    var results = std.array_list.Managed(Result).init(allocator);
    defer {
        for (results.items) |r| if (r.error_msg) |m| allocator.free(m);
        results.deinit();
    }
    
    var deleted_count: u64 = 0;
    var failed_count: u64 = 0;
    var deletion_error_occurred = false;
    var likely_orphan_found = false;

    for (plan.items) |it| {
        switch (it) {
            .sysv => |s| if (s.classification == .likely_orphan) { likely_orphan_found = true; },
            .posix => |p| if (p.classification == .likely_orphan) { likely_orphan_found = true; },
        }
    }

    if (cfg.apply) {
        if (plan.items.len > 0) {
            if (cfg.json and !cfg.yes) {
                return error.MissingYesForJsonApply;
            }
            if (!cfg.yes and !cfg.json) {
                const stderr_file = std.fs.File.stderr();
                var stderr = stderr_file.deprecatedWriter();
                try stderr.print("\nWARNING: You are about to DELETE {d} items totaling {d} bytes.\n", .{plan.items.len, planned_total_bytes});
                try stderr.print("Type DELETE to confirm: ", .{});
                const stdin_file = std.fs.File.stdin();
                var line_buf: [64]u8 = undefined;
                var line_len: usize = 0;
                while (line_len < line_buf.len) {
                    var byte_buf: [1]u8 = undefined;
                    const n = try stdin_file.read(&byte_buf);
                    if (n == 0) break;
                    if (byte_buf[0] == '\n') break;
                    line_buf[line_len] = byte_buf[0];
                    line_len += 1;
                }
                if (line_len > 0) {
                    const line = line_buf[0..line_len];
                    const trimmed = std.mem.trim(u8, line, " \r\t");
                    if (!std.mem.eql(u8, trimmed, "DELETE")) {
                         try stderr.print("Aborted.\n", .{});
                         return 0; // Abort (not error)
                    }
                } else {
                    return 0;
                }
            }

            for (plan.items) |it| {
                var res = Result{ .kind = "unknown", .id = null, .path = null, .attempted = false, .deleted = false, .error_msg = null };
                
                switch (it) {
                    .sysv => |s| {
                        res.kind = "sysv";
                        res.id = s.shmid;
                        // Verification
                        if (sysv_mod.verify_item(s)) |_| {
                            res.attempted = true;
                            const ret = c_shm.shmctl(s.shmid, c_shm.IPC_RMID, null);
                            if (ret == 0) {
                                res.deleted = true;
                                deleted_count += 1;
                            } else {
                                failed_count += 1;
                                deletion_error_occurred = true;
                                const err = std.c._errno().*;
                                res.error_msg = try std.fmt.allocPrint(allocator, "errno={d}", .{err});
                            }
                        } else |ver_err| {
                             res.error_msg = try std.fmt.allocPrint(allocator, "verification_failed: {s}", .{@errorName(ver_err)});
                        }
                    },
                    .posix => |p| {
                        res.kind = "posix";
                        res.path = p.path;
                        if (posix_mod.verify_item_alloc(allocator, p)) |_| {
                             res.attempted = true;
                             const path_z = try allocator.dupeZ(u8, p.path);
                             defer allocator.free(path_z);
                             const ret = unlink(path_z);
                             if (ret == 0) {
                                 res.deleted = true;
                                 deleted_count += 1;
                             } else {
                                 failed_count += 1;
                                 deletion_error_occurred = true;
                                 const err = std.c._errno().*;
                                 res.error_msg = try std.fmt.allocPrint(allocator, "errno={d}", .{err});
                             }
                        } else |ver_err| {
                             res.error_msg = try std.fmt.allocPrint(allocator, "verification_failed: {s}", .{@errorName(ver_err)});
                        }
                    }
                }
                try results.append(res);
            }
        }
    }

    if (cfg.json) {
        const stdout_file = std.fs.File.stdout();
        var writer = stdout_file.deprecatedWriter();

        const JsonReapItem = struct {
            kind: []const u8,
            id: ?i32 = null, // sysv only
            path: ?[]const u8 = null, // posix only
            bytes: u64,
            reasons: []const []const u8,
        };

        const JsonReapResult = struct {
            kind: []const u8,
            id: ?i32,
            path: ?[]const u8,
            attempted: bool,
            deleted: bool,
            error_msg: ?[]const u8, // Renamed from 'error' to avoid reserved word conflict
        };

        const JsonReap = struct {
            apply: bool,
            dry_run: bool,
            force: bool,
            partial_proc_access_sysv: bool,
            partial_proc_access_posix: bool,
            planned_total_bytes: u64,
            planned_deletions: []const JsonReapItem,
            results: []const JsonReapResult,
            deleted_count: u64,
            failed_count: u64,
        };
        
        var json_planned = std.array_list.Managed(JsonReapItem).init(allocator);
        defer json_planned.deinit();

        for (plan.items) |it| {
             switch (it) {
                .sysv => |s| {
                    try json_planned.append(.{
                        .kind = "sysv",
                        .id = s.shmid,
                        .bytes = s.bytes,
                        .reasons = s.reasons.items,
                    });
                },
                .posix => |p| {
                    try json_planned.append(.{
                        .kind = "posix",
                        .path = p.path,
                        .bytes = p.bytes,
                        .reasons = p.reasons.items,
                    });
                }
            }
        }

        var json_results = std.array_list.Managed(JsonReapResult).init(allocator);
        defer json_results.deinit();

        for (results.items) |res| {
            try json_results.append(.{
                .kind = res.kind,
                .id = res.id,
                .path = res.path,
                .attempted = res.attempted,
                .deleted = res.deleted,
                .error_msg = res.error_msg,
            });
        }
        
        const out_obj = JsonReap{
            .apply = cfg.apply,
            .dry_run = dry_run,
            .force = cfg.force,
            .partial_proc_access_sysv = partial_proc_access_sysv,
            .partial_proc_access_posix = partial_proc_access_posix,
            .planned_total_bytes = planned_total_bytes,
            .planned_deletions = json_planned.items,
            .results = json_results.items,
            .deleted_count = deleted_count,
            .failed_count = failed_count,
        };

        try writer.print("{f}", .{std.json.fmt(out_obj, .{})});
    } else {
        // Human output
        const stdout_file = std.fs.File.stdout();
        var writer = stdout_file.deprecatedWriter();
        try writer.print("REAP PLAN (dry_run={})\n", .{dry_run});
        try writer.print("TYPE   ID                                                           SIZE\n", .{});
        for (plan.items) |it| {
             switch (it) {
                .sysv => |s| try writer.print("sysv   {d:<60} {d}\n", .{s.shmid, s.bytes}),
                .posix => |p| {
                    const base = std.fs.path.basename(p.path);
                    try writer.print("posix  {s:<60} {d}\n", .{base, p.bytes});
                }
             }
        }
        if (cfg.apply) {
             try writer.print("\nRESULTS:\n", .{});
             for (results.items) |res| {
                 const id_s = if (res.id) |i| try std.fmt.allocPrint(allocator, "{d}", .{i}) else res.path orelse "???";
                 defer if (res.id != null) allocator.free(id_s);
                 
                 if (res.deleted) {
                     try writer.print("DELETED {s} {s}\n", .{res.kind, id_s});
                 } else {
                     try writer.print("FAILED  {s} {s}: {s}\n", .{res.kind, id_s, res.error_msg orelse "unknown"});
                 }
             }
             try writer.print("Sum: {d} deleted, {d} failed.\n", .{deleted_count, failed_count});
        }
    }
    
    // Exit Logic
    if (cfg.apply) {
        if (failed_count > 0) return 2;
        // "Return 0 if no deletion attempts failed... regardless of whether orphans existed before."
        if (deletion_error_occurred) return 2; // failed_count tracks most, logic matches.
        
        // "Return 2 if any deletion attempt failed OR if partial proc access prevents confident decisions but --apply was requested and you skipped items due to that"
        // If partial_proc_access triggered "unknown" classification, then "eligible" would be false.
        // We need to know if we skipped any likely_orphans due to uncertainty?
        // Actually, if we mark them as unknown, they are not likely_orphan.
        // But if we requested --apply, and we have partial errors...
        // The user requirement says: "treat conservative skipping as not a failure unless deletion was attempted; however you must surface it in JSON and non-JSON text output"
        // Wait, "Return 2 ... if partial proc access prevents ... and you skipped items".
        // How do I know if I skipped items due to that vs just not orphans?
        // If `partial_proc_access` is true, AND I scanned items that MIGHT match if I knew more?
        // It's safer to say: If partial access occurred, and we are in apply mode, we might have missed some.
        // BUT strict requirement: "Return 0 if no deletion attempts failed ... regardless of orphans".
        // "Return 2 if ... OR if partial proc access ... and you skipped items"
        // Maybe just check `partial_proc_access_sysv/posix`.
        // If these are true, we potentially skipped.
        // So `if (cfg.apply and (partial_proc_access_sysv or partial_proc_access_posix) and failed_count == 0)` -> return 2?
        // "treat conservative skipping as not a failure UNLESS deletion was attempted"?
        // No, "Return 2 if ... OR if [skipping happens]".
        // So if skipped, return 2.
        if (partial_proc_access_sysv or partial_proc_access_posix) return 2;
        
        return 0;
    } else {
        // Dry run
        if (partial_proc_access_sysv or partial_proc_access_posix) return 2;
        if (likely_orphan_found) return 1;
        return 0;
    }
}

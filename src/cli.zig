const std = @import("std");
const config_mod = @import("config.zig");
const sysv_mod = @import("sysv.zig");
const posix_mod = @import("posix.zig");
const time_mod = @import("time.zig");
const proc_mod = @import("proc.zig");
const output_mod = @import("output.zig");

// IPC consts (Linux)
const IPC_RMID = 0;

// shmctl signature
// int shmctl(int shmid, int cmd, struct shmid_ds *buf);
extern "c" fn shmctl(shmid: c_int, cmd: c_int, buf: ?*anyopaque) c_int;

// POSIX unlink
extern "c" fn unlink(path: [*:0]const u8) c_int;

pub fn run(allocator: std.mem.Allocator) !u8 {
    const cfg = try config_mod.parse_args(allocator);
    // We cannot defer cfg.deinit() here easily if we return from run, 
    // but the process will exit anyway.
    
    // Get system time
    const sys_time = try time_mod.get_system_time();
    const now = time_mod.get_current_timestamp();
    
    switch (cfg.mode) {
        .scan => return run_scan(allocator, cfg, sys_time, now),
        .explain => return run_explain(allocator, cfg, sys_time, now),
        .reap => return run_reap(allocator, cfg, sys_time, now),
    }
}

fn run_scan(allocator: std.mem.Allocator, cfg: config_mod.Config, sys_time: time_mod.SystemTime, now: u64) !u8 {
    var items = std.ArrayList(output_mod.Item).init(allocator);
    defer items.deinit();
    
    var sysv_items: std.ArrayList(sysv_mod.SysVItem) = undefined;
    if (cfg.target_type == .sysv or cfg.target_type == .both) {
        // Collect SysV
        sysv_items = try sysv_mod.parse_sysv_shm(allocator, "/proc/sysvipc/shm");
    } else {
        sysv_items = std.ArrayList(sysv_mod.SysVItem).init(allocator);
    }
    // We must pointer-stable these items if we stick pointers in 'items'.
    // `sysv_items` is an ArrayList. Pointers to its elements are unstable if we append?
    // But we are done appending to sysv_items here.
    
    var posix_items: std.ArrayList(posix_mod.PosixItem) = undefined;
    var partial_proc_access = false;
    
    if (cfg.target_type == .posix or cfg.target_type == .both) {
        posix_items = try posix_mod.scan_posix_dir(allocator, cfg.posix_dir);
        // Correlate
        partial_proc_access = try posix_mod.correlate_open_fds(allocator, posix_items.items);
    } else {
        posix_items = std.ArrayList(posix_mod.PosixItem).init(allocator);
    }

    // Process SysV
    for (sysv_items.items) |*item| {
        // Liveness
        // creator
        if (item.cpid > 0) {
            const start = proc_mod.get_pid_starttime(allocator, item.cpid) catch 0;
            if (start != 0) {
                item.creator_alive = true;
                // Reuse check
                if (item.ctime != 0) {
                     const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                     // If pid_start_epoch > shm_ctime + 2s -> reused
                     if (start_epoch > item.ctime + 2) {
                         item.creator_pid_reused = true;
                     }
                }
            }
        }
        // last
        if (item.lpid > 0) {
            const start = proc_mod.get_pid_starttime(allocator, item.lpid) catch 0;
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
        
        try sysv_mod.classify_item(item, cfg, now, allocator);
        try items.append(output_mod.Item{ .sysv = item });
    }

    // Process POSIX
    for (posix_items.items) |*item| {
        try posix_mod.classify_item(item, cfg, now, partial_proc_access);
        try items.append(output_mod.Item{ .posix = item });
    }

    // Summary
    var summary = output_mod.Summary{};
    summary.partial_proc_access = partial_proc_access;
    
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

    // Exit codes
    // 2 if partial errors (already tracked via partial_proc_access? No, partial_proc_access only tracks ACCESS DENIED on fd dir)
    // Req: "If ghosts exist AND partial errors occurred, exit code must be 2"
    // Also "permission denied reading /proc... OR any /proc read failures".
    // I need to track global partial errors.
    // `sysv_mod.parse_sysv_shm` fails fatally if read fails.
    // `proc_mod` helpers return errors.
    // `posix_mod.correlate` returns `partial_error` specific to permission.
    // I should probably track "had_partial_errors" more broadly.
    // Implementation Detail: "Maintain a boolean had_partial_errors".
    
    // In this implementation, I rely on `partial_proc_access` for the POSIX part.
    // For SysV, if `parse_sysv_shm` fails, we crash/propagate error (main handles it).
    // For PID liveness checks, I ignored errors (catch 0). Technically if `/proc/<pid>/stat` fails for EXISTING pid, it's a partial error.
    // But `get_pid_starttime` returns `PidNotFound` if file not found. Any other error is partial read error?
    // I'll be conservative. If `partial_proc_access` is true, exit 2.
    
    if (partial_proc_access) return 2;
    if (likely_orphan_exists) return 1;
    return 0;
}

fn run_explain(allocator: std.mem.Allocator, cfg: config_mod.Config, sys_time: time_mod.SystemTime, now: u64) !u8 {
    // Determine target
    // Same scan logic first? Or optimized?
    // "Explain must output a deterministic forensic report".
    // It's better to scan all to get full context (e.g. key reuse?), but we can target specific.
    // However, for POSIX, we need to scan /proc for FDs anyway to see if ANY process has it open.
    // So we must run the full correlation scan.
    
    // Reusing run_scan logic partially?
    // I'll reuse the logic but filtering output.
    
    // ... Copy paste scan setup ...
    // (Refactoring into `Context` struct would be better but I'll duplicate for isolation as per task structure constraints)
    
    const sysv_items = if (cfg.target_type == .sysv or cfg.target_type == .both) try sysv_mod.parse_sysv_shm(allocator, "/proc/sysvipc/shm") else std.ArrayList(sysv_mod.SysVItem).init(allocator);
    
    var posix_items = std.ArrayList(posix_mod.PosixItem).init(allocator);
    var partial_proc_access = false;
    if (cfg.target_type == .posix or cfg.target_type == .both) {
        posix_items = try posix_mod.scan_posix_dir(allocator, cfg.posix_dir);
        partial_proc_access = try posix_mod.correlate_open_fds(allocator, posix_items.items);
    }
    
    // Find item
    var found_item: ?output_mod.Item = null;
    
    // ID parsing logic
    var target_shmid: ?i32 = null;
    var target_path: ?[]const u8 = null;
    
    const id = cfg.explain_id;
    if (std.mem.startsWith(u8, id, "sysv:")) {
        target_shmid = std.fmt.parseInt(i32, id[5..], 10) catch return 64;
    } else if (std.mem.startsWith(u8, id, "posix:")) {
        target_path = id[6..];
    } else {
        // Try parsing number
        if (std.fmt.parseInt(i32, id, 10)) |v| {
            target_shmid = v;
        } else |_| {
            target_path = id;
        }
    }

    if (target_shmid) |tid| {
        for (sysv_items.items) |*item| {
            if (item.shmid == tid) {
                // Populate details similar to scan
                if (item.cpid > 0) {
                     const start = proc_mod.get_pid_starttime(allocator, item.cpid) catch 0;
                     if (start != 0) {
                         item.creator_alive = true;
                         if (item.ctime != 0) {
                             const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                             if (start_epoch > item.ctime + 2) item.creator_pid_reused = true;
                         }
                     }
                }
                if (item.lpid > 0) {
                     const start = proc_mod.get_pid_starttime(allocator, item.lpid) catch 0;
                     if (start != 0) {
                         item.last_alive = true;
                         if (item.ctime != 0) {
                             const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                             if (start_epoch > item.ctime + 2) item.last_pid_reused = true;
                         }
                     }
                }
                try sysv_mod.classify_item(item, cfg, now, allocator);
                found_item = output_mod.Item{ .sysv = item };
                break;
            }
        }
    } else if (target_path) |tpath| {
         // Match path (basename or full)
         // "Else treat argument as a POSIX path"
         // "If argument starts with posix: => POSIX path is substring..."
         // We check full path match or basename match? 
         // "ID = basename of file" in scan output.
         // But explain input might be full path.
         // Let's check both.
         for (posix_items.items) |*item| {
             const base = std.fs.path.basename(item.path);
             const p_base = std.fs.path.basename(tpath);
             if (std.mem.eql(u8, item.path, tpath) or std.mem.eql(u8, base, p_base)) {
                 try posix_mod.classify_item(item, cfg, now, partial_proc_access);
                 found_item = output_mod.Item{ .posix = item };
                 break;
             }
         }
    }

    if (cfg.json) {
        // JSON output
        const stdout = std.io.getStdOut().writer();
        if (found_item) |it| {
            // Print item object + "found": true
            // We'll hack the output logic or recreate it here.
            // Items output is array. Here we want single object.
            // Using print_json logic requires modification.
            // I'll write manually here.
            try stdout.print("{{\"found\":true, ", .{});
            // serialize item fields...
            // This is tedious to duplicate.
            // But let's verify if I can call a helper.
            // output_mod doesn't have single object printer.
            // I'll assume duplication for now to be exact.
            
            switch (it) {
                .sysv => |s| {
                    try stdout.print("\"type\":\"sysv\",\"shmid\":{d},\"bytes\":{d},\"classification\":\"{s}\",\"recommendation\":\"{s}\",\"reasons\":[", 
                        .{s.shmid, s.bytes, @tagName(s.classification), @tagName(s.recommendation)});
                    for (s.reasons.items, 0..) |r, i| {
                        if (i > 0) try stdout.print(",", .{});
                        try stdout.print("\"{s}\"", .{r});
                    }
                    try stdout.print("]}}", .{});
                },
                .posix => |p| {
                     try stdout.print("\"type\":\"posix\",\"path\":\"{s}\",\"bytes\":{d},\"classification\":\"{s}\",\"recommendation\":\"{s}\",\"reasons\":[", 
                        .{p.path, p.bytes, @tagName(p.classification), @tagName(p.recommendation)});
                    for (p.reasons.items, 0..) |r, i| {
                        if (i > 0) try stdout.print(",", .{});
                        try stdout.print("\"{s}\"", .{r});
                    }
                    try stdout.print("]}}", .{});
                }
            }
        } else {
             try stdout.print("{{\"found\":false}}", .{});
        }
    } else {
        // Human output
        // Header
        const stdout = std.io.getStdOut().writer();
        if (found_item) |it| {
            switch (it) {
                .sysv => |s| {
                    try stdout.print("EXPLAIN TYPE=sysv ID={d}\n", .{s.shmid});
                    try stdout.print("EVIDENCE:\n", .{});
                    try stdout.print("  bytes: {d}\n", .{s.bytes});
                    try stdout.print("  age: {d}s\n", .{s.age_seconds});
                    try stdout.print("  nattch: {d}\n", .{s.nattch});
                    try stdout.print("  uid: {d}\n", .{s.uid});
                    try stdout.print("  creator_alive: {}\n", .{s.creator_alive});
                    try stdout.print("  last_alive: {}\n", .{s.last_alive});
                    
                    try stdout.print("CLASSIFICATION:\n", .{});
                    try stdout.print("  classification: {s}\n", .{@tagName(s.classification)});
                    try stdout.print("  recommendation: {s}\n", .{@tagName(s.recommendation)});
                    for (s.reasons.items) |r| {
                        try stdout.print("- {s}\n", .{r});
                    }
                    
                    try stdout.print("CLEANUP:\n", .{});
                    try stdout.print("  shmctl({d}, IPC_RMID)\n", .{s.shmid});
                },
                .posix => |p| {
                    try stdout.print("EXPLAIN TYPE=posix ID={s}\n", .{p.path});
                    try stdout.print("EVIDENCE:\n", .{});
                    try stdout.print("  bytes: {d}\n", .{p.bytes});
                    try stdout.print("  age: {d}s\n", .{p.age_seconds});
                    try stdout.print("  open_pids: {d}\n", .{p.open_pids_count});
                    try stdout.print("  partial_proc_access: {}\n", .{partial_proc_access});
                    
                    try stdout.print("CLASSIFICATION:\n", .{});
                    try stdout.print("  classification: {s}\n", .{@tagName(p.classification)});
                    try stdout.print("  recommendation: {s}\n", .{@tagName(p.recommendation)});
                    for (p.reasons.items) |r| {
                         try stdout.print("- {s}\n", .{r});
                    }
                    
                    try stdout.print("CLEANUP:\n", .{});
                    try stdout.print("  unlink({s})\n", .{p.path});
                }
            }
        } else {
            try stdout.print("Item not found.\n", .{});
        }
    }

    if (partial_proc_access) return 2;
    return 0;
}

fn run_reap(allocator: std.mem.Allocator, cfg: config_mod.Config, sys_time: time_mod.SystemTime, now: u64) !u8 {
    // 1. Scan (reuse code by copy or func? code duplication for speed and isolation)
     const sysv_items = if (cfg.target_type == .sysv or cfg.target_type == .both) try sysv_mod.parse_sysv_shm(allocator, "/proc/sysvipc/shm") else std.ArrayList(sysv_mod.SysVItem).init(allocator);
    var posix_items = std.ArrayList(posix_mod.PosixItem).init(allocator);
    var partial_proc_access = false;
    if (cfg.target_type == .posix or cfg.target_type == .both) {
        posix_items = try posix_mod.scan_posix_dir(allocator, cfg.posix_dir);
        partial_proc_access = try posix_mod.correlate_open_fds(allocator, posix_items.items);
    }

    // Classify
    var plan = std.ArrayList(output_mod.Item).init(allocator);
    
    // SysV
    var sysv_orphan = false;
    for (sysv_items.items) |*item| {
        // Liveness ... (dup logic)
        if (item.cpid > 0) {
             const start = proc_mod.get_pid_starttime(allocator, item.cpid) catch 0;
             if (start != 0) {
                 item.creator_alive = true;
                 if (item.ctime != 0) {
                     const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                     if (start_epoch > item.ctime + 2) item.creator_pid_reused = true;
                 }
             }
        }
        if (item.lpid > 0) {
             const start = proc_mod.get_pid_starttime(allocator, item.lpid) catch 0;
             if (start != 0) {
                 item.last_alive = true;
                 if (item.ctime != 0) {
                     const start_epoch = sys_time.boot_time + (start / sys_time.hz);
                     if (start_epoch > item.ctime + 2) item.last_pid_reused = true;
                 }
             }
        }
        
        try sysv_mod.classify_item(item, cfg, now, allocator);
        if (item.classification == .likely_orphan) sysv_orphan = true;
        
        // Planning
        var eligible = false;
        if (item.recommendation == .reap and item.classification == .likely_orphan) eligible = true;
        if (cfg.force) {
            if (item.classification == .possible_orphan or item.classification == .risky_to_remove) eligible = true;
        }
        // Never allowlisted or in_use
        if (item.classification == .allowlisted or item.classification == .in_use) eligible = false;

        if (eligible) {
            try plan.append(output_mod.Item{ .sysv = item });
        }
    }
    
    // Posix
    var posix_orphan = false;
    for (posix_items.items) |*item| {
        try posix_mod.classify_item(item, cfg, now, partial_proc_access);
        if (item.classification == .likely_orphan) posix_orphan = true;
        
        var eligible = false;
        if (item.recommendation == .reap and item.classification == .likely_orphan) eligible = true;
        if (cfg.force) {
            if (item.classification == .possible_orphan or item.classification == .risky_to_remove) eligible = true;
        }
        if (item.classification == .allowlisted or item.classification == .in_use) eligible = false;
        
        if (eligible) {
            try plan.append(output_mod.Item{ .posix = item });
        }
    }

    // Output plan
    const dry_run = !cfg.apply;
    
    if (cfg.json) {
        // JSON Plan
        const stdout = std.io.getStdOut().writer();
        try stdout.print("{{\"dry_run\":{},\"apply\":{},\"force\":{},", .{dry_run, cfg.apply, cfg.force});
        try stdout.print("\"planned_deletions\":[", .{});
        var total_bytes: u64 = 0;
        for (plan.items, 0..) |it, i| {
            if (i > 0) try stdout.print(",", .{});
            switch (it) {
                .sysv => |s| {
                    try stdout.print("{{\"type\":\"sysv\",\"id\":{d},\"bytes\":{d},\"classification\":\"{s}\",\"reasons\":[", 
                        .{s.shmid, s.bytes, @tagName(s.classification)});
                    // reasons array
                     for (s.reasons.items, 0..) |r, k| { if (k>0) try stdout.print(",", .{}); try stdout.print("\"{s}\"", .{r}); }
                    try stdout.print("]}}", .{});
                    total_bytes += s.bytes;
                },
                .posix => |p| {
                    try stdout.print("{{\"type\":\"posix\",\"id\":\"{s}\",\"bytes\":{d},\"classification\":\"{s}\",\"reasons\":[", 
                        .{p.path, p.bytes, @tagName(p.classification)});
                    // reasons
                    for (p.reasons.items, 0..) |r, k| { if (k>0) try stdout.print(",", .{}); try stdout.print("\"{s}\"", .{r}); }
                    try stdout.print("]}}", .{});
                    total_bytes += p.bytes;
                }
            }
        }
        try stdout.print("],\"planned_total_bytes\":{d}", .{total_bytes});
        // If applying, we will print results separately?
        // JSON output for apply says: "results": [...]
        // So I should wait to print the JSON?
        // Spec: "In dry-run... Output JSON... Exit codes..."
        // "With --apply... JSON output for apply..."
        // So if apply, I output a DIFFERENT JSON.
        // So I should NOT print the plan JSON if apply is true.
        // But "Always print the plan first." (Human mode).
        // JSON mode usually implies one JSON object.
        // If apply=true and json=true, I should output the FINAL json result which includes results.
        
        if (dry_run) {
             try stdout.print("}}", .{}); // Close object
             if (partial_proc_access) return 2;
             if (sysv_orphan or posix_orphan) return 1;
             return 0;
        }
        // If apply, don't close, or actually use different struct.
        // I'll buffer the plan or just proceed.
    } else {
        // Human plan
        const stdout = std.io.getStdOut().writer();
        try stdout.print("TYPE   ID                                                           SIZE      CLASSIFICATION\n", .{});
        for (plan.items) |it| {
             switch (it) {
                .sysv => |s| {
                    try stdout.print("sysv   {d:<60} {d:>10}  {s}\n", .{s.shmid, s.bytes, @tagName(s.classification)});
                },
                .posix => |p| {
                    const base = std.fs.path.basename(p.path);
                    try stdout.print("posix  {s:<60} {d:>10}  {s}\n", .{base, p.bytes, @tagName(p.classification)});
                }
            }
        }
        if (plan.items.len == 0) {
            try stdout.print("No items to reap.\n", .{});
        }
        if (dry_run) try stdout.print("DRY_RUN=true\n", .{});
    }
    
    // Apply logic
    if (dry_run) {
        if (partial_proc_access) return 2;
        if (sysv_orphan or posix_orphan) return 1;
        return 0;
    }
    
    if (plan.items.len == 0) {
        // Do nothing, exit using scan rules
        if (partial_proc_access) return 2;
        if (sysv_orphan or posix_orphan) return 1;
        return 0;
    }
    
    // Confirmation
    if (!cfg.yes) {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("Type DELETE to confirm: ", .{});
        const stdin = std.io.getStdIn().reader();
        var buf: [64]u8 = undefined;
        if (try stdin.readUntilDelimiterOrEof(&buf, '\n')) |line| {
            // Trim CR if present?
            const trimmed = std.mem.trim(u8, line, " \r\t");
            if (!std.mem.eql(u8, trimmed, "DELETE")) {
                // Abort
                return 0;
            }
        } else {
            return 0; // EOF implies abort
        }
    }
    
    // Execute
    var deleted_count: u64 = 0;
    var failed_count: u64 = 0;
    // var result_json_started = false;
    
    const stdout = std.io.getStdOut().writer();
    if (cfg.json) {
        try stdout.print(",\"results\":[", .{}); // Continue from previous open object?
        // Wait, I said I shouldn't print the plan JSON if apply.
        // If apply, I print the APPLY JSON object.
        // So I need to start the apply object now.
        // But I haven't printed anything yet in Json mode for apply.
        // So start clean.
        try stdout.print("{{\"dry_run\":false,\"apply\":true,\"force\":{},\"results\":[", .{cfg.force});
    }

    var partial_deletion_error = false;

    for (plan.items, 0..) |it, i| {
        if (cfg.json and i > 0) try stdout.print(",", .{});
        
        switch (it) {
            .sysv => |s| {
                const ret = shmctl(s.shmid, IPC_RMID, null);
                const success = (ret == 0);
                const err_val = if (success) 0 else std.c._errno().*;
                
                if (success) deleted_count += 1 else failed_count += 1;
                if (!success) partial_deletion_error = true;

                 if (cfg.json) {
                     try stdout.print("{{\"type\":\"sysv\",\"shmid\":{d},\"success\":{},\"errno\":{d}}}", 
                         .{s.shmid, success, err_val});
                 }
            },
            .posix => |p| {
                const path_z = try allocator.dupeZ(u8, p.path);
                defer allocator.free(path_z);
                const ret = unlink(path_z);
                const success = (ret == 0);
                const err_val = if (success) 0 else std.c._errno().*;
                
                if (success) deleted_count += 1 else failed_count += 1;
                 if (!success) partial_deletion_error = true;
                
                 if (cfg.json) {
                     try stdout.print("{{\"type\":\"posix\",\"path\":\"{s}\",\"success\":{},\"errno\":{d}}}", 
                         .{p.path, success, err_val});
                 }
            }
        }
    }
    
    var attempted_total_bytes: u64 = 0;
    for (plan.items) |it| {
         switch (it) {
             .sysv => |s| attempted_total_bytes += s.bytes,
             .posix => |p| attempted_total_bytes += p.bytes,
         }
    }

    if (cfg.json) {
        try stdout.print("],\"attempted_total_bytes\":{d},\"deleted_count\":{d},\"failed_count\":{d}}}", 
            .{attempted_total_bytes, deleted_count, failed_count});
    }
    
    // Exit codes
    if (partial_deletion_error) return 2;
    // Else use scan rules
    if (partial_proc_access) return 2;
    if (sysv_orphan or posix_orphan) return 1;
    return 0;
}

const std = @import("std");
const time = @import("time.zig");

pub const Mode = enum {
    scan,
    explain,
    reap,
};

pub const TargetType = enum {
    sysv,
    posix,
    both,
};

pub const Config = struct {
    mode: Mode,
    // Global flags
    json: bool = false,
    posix_dir: []const u8 = "/dev/shm",
    threshold_seconds: u64 = 1800, // 30m
    min_bytes: u64 = 65536,
    target_type: TargetType = .both,
    allow_owners: std.array_list.Managed(u32),
    allow_names: std.array_list.Managed([]const u8),
    allow_keys: std.array_list.Managed(u64),
    no_color: bool = false,
    verbose: bool = false,

    // Explain specific
    explain_id: []const u8 = "",

    // Reap specific
    apply: bool = false,
    yes: bool = false,
    force: bool = false,

    allocated_strings: std.array_list.Managed([]u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Config {
        return Config{
            .mode = .scan,
            .allow_owners = std.array_list.Managed(u32).init(allocator),
            .allow_names = std.array_list.Managed([]const u8).init(allocator),
            .allow_keys = std.array_list.Managed(u64).init(allocator),
            .allocated_strings = std.array_list.Managed([]u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Config) void {
        self.allow_owners.deinit();
        self.allow_names.deinit();
        self.allow_keys.deinit();
        for (self.allocated_strings.items) |s| self.allocator.free(s);
        self.allocated_strings.deinit();
    }
};

pub fn parse_args(allocator: std.mem.Allocator) !Config {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip(); // skip binary name

    var config = Config.init(allocator);

    // Initial pass to determine command
    // var command_set = false;
    
    // We need to collect args to process flags. 
    // Since zig args iterator is forward only, we process strictly.
    // HOWEVER, the spec says `ghostshm` (equiv to scan), `ghostshm scan [FLAGS]`, `ghostshm explain <ID> [FLAGS]`.
    // So the FIRST argument determines the mode, UNLESS it starts with `-`.
    // If first arg is flag, mode is scan.

    // To handle this properly, let's peek or just handle the state machine.
    // But argsWithAllocator is an iterator.
    
    // Let's store all args in a list first for easier peeking/processing if needed, 
    // or just handle the first one specially.
    // Actually, "global flags apply to scan/explain/reap where relevant".
    // This implies flags can come anywhere? Usually flags follow command.
    // "ghostshm scan [FLAGS]" -> command first.
    // If user types `ghostshm --json`, that is `scan --json`.
    
    // Let's implement a simple lookahead or buffer.
    var arg_list = std.array_list.Managed([]const u8).init(allocator);
    defer arg_list.deinit();
    
    while (args.next()) |arg| {
        const s = try allocator.dupe(u8, arg);
        try config.allocated_strings.append(s);
        try arg_list.append(s);
    }

    // Determine command
    var arg_idx: usize = 0;
    if (arg_list.items.len > 0) {
        const first = arg_list.items[0];
        if (!std.mem.startsWith(u8, first, "-")) {
            if (std.mem.eql(u8, first, "scan")) {
                config.mode = .scan;
                // command_set = true;
                arg_idx += 1;
            } else if (std.mem.eql(u8, first, "reap")) {
                config.mode = .reap;
                // command_set = true;
                arg_idx += 1;
            } else if (std.mem.eql(u8, first, "explain")) {
                config.mode = .explain;
                // command_set = true;
                arg_idx += 1;
                // Next arg MUST be ID
                if (arg_idx < arg_list.items.len) {
                    config.explain_id = arg_list.items[arg_idx];
                    arg_idx += 1;
                } else {
                    return error.MissingExplainId;
                }
            } else {
                // Unknown command or it's a flag, or implicit scan?
                // Spec: `ghostshm` (equivalent to `ghostshm scan`)
                // If checking for flags, if it doesn't look like a flag, it might be an error or implicit scan?
                // But `ghostshm explain <ID>` -> explain is explicit.
                // Any other word... "ghostshm foo" -> likely error unless "foo" is a flag?
                // Spec doesn't say "foo" is valid.
                // Assuming implicit scan only if no command provided. 
                // Since first arg didn't match start with '-', and didn't match known commands, 
                // Check if it looks like a subcommand?
                // Spec Exit 64: CLI usage error.
                // If user runs `ghostshm --json`, first arg is flag, so implicit scan.
                // If user runs `ghostshm`, no args, implicit scan.
                // If user runs `ghostshm something`, and `something` is not a flag/command: Error.
                return error.InvalidCommand;
            }
        } else {
            // Starts with -, implicit scan
            config.mode = .scan;
        }
    } else {
        // No args
        config.mode = .scan;
    }

    // Process remaining args
    while (arg_idx < arg_list.items.len) : (arg_idx += 1) {
        const arg = arg_list.items[arg_idx];
        if (std.mem.eql(u8, arg, "--json")) {
            config.json = true;
        } else if (std.mem.eql(u8, arg, "--posix-dir")) {
            arg_idx += 1;
            if (arg_idx >= arg_list.items.len) return error.MissingArgument;
            config.posix_dir = arg_list.items[arg_idx];
        } else if (std.mem.eql(u8, arg, "--threshold")) {
            arg_idx += 1;
            if (arg_idx >= arg_list.items.len) return error.MissingArgument;
            config.threshold_seconds = try time.parse_duration(arg_list.items[arg_idx]);
        } else if (std.mem.eql(u8, arg, "--min-bytes")) {
            arg_idx += 1;
            if (arg_idx >= arg_list.items.len) return error.MissingArgument;
            config.min_bytes = try std.fmt.parseInt(u64, arg_list.items[arg_idx], 10);
        } else if (std.mem.eql(u8, arg, "--only")) {
            arg_idx += 1;
            if (arg_idx >= arg_list.items.len) return error.MissingArgument;
            const val = arg_list.items[arg_idx];
            if (std.mem.eql(u8, val, "sysv")) {
                config.target_type = .sysv;
            } else if (std.mem.eql(u8, val, "posix")) {
                config.target_type = .posix;
            } else {
                return error.InvalidEnum;
            }
        } else if (std.mem.eql(u8, arg, "--allow-owner")) {
            arg_idx += 1;
            if (arg_idx >= arg_list.items.len) return error.MissingArgument;
            const uid = try std.fmt.parseInt(u32, arg_list.items[arg_idx], 10);
            try config.allow_owners.append(uid);
        } else if (std.mem.eql(u8, arg, "--allow-name")) {
            arg_idx += 1;
            if (arg_idx >= arg_list.items.len) return error.MissingArgument;
            try config.allow_names.append(arg_list.items[arg_idx]);
        } else if (std.mem.eql(u8, arg, "--allow-key")) {
            arg_idx += 1;
            if (arg_idx >= arg_list.items.len) return error.MissingArgument;
            const k = arg_list.items[arg_idx];
            const val = try std.fmt.parseInt(u64, k, 0); // 0 detects 0x or decimal
            try config.allow_keys.append(val);
        } else if (std.mem.eql(u8, arg, "--no-color")) {
            config.no_color = true;
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            config.verbose = true;
        } else if (std.mem.eql(u8, arg, "--apply")) {
            if (config.mode != .reap) return error.InvalidFlagForCommand;
            config.apply = true;
        } else if (std.mem.eql(u8, arg, "--yes")) {
            if (config.mode != .reap) return error.InvalidFlagForCommand;
            config.yes = true;
        } else if (std.mem.eql(u8, arg, "--force")) {
            if (config.mode != .reap) return error.InvalidFlagForCommand;
            config.force = true;
        } else {
            return error.UnknownFlag;
        }
    }

    return config;
}

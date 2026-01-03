const std = @import("std");
const cli = @import("cli.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const exit_code = cli.run(allocator) catch |err| {
        switch (err) {
            error.InvalidCommand,
            error.MissingArgument,
            error.InvalidEnum,
            error.InvalidFlagForCommand,
            error.UnknownFlag,
            error.InvalidDuration,
            error.MissingExplainId,
            error.Overflow, // integer parsing
            error.InvalidCharacter // integer parsing
            => {
                std.debug.print("Error: {s}\nUsage: ghostshm scan|explain|reap [flags]\n", .{@errorName(err)});
                std.process.exit(64);
            },
            
            // 70 for internal/fatal
            error.HeaderMissing,
            error.MissingRequiredColumn,
            error.ParseError,
            error.FileReadError => {
                 std.debug.print("Fatal internal error: {s}\n", .{@errorName(err)});
                 std.process.exit(70);
            },
            
            else => {
                // If IO error reading /proc/sysvipc/shm when it is required: 70.
                std.debug.print("Unexpected error: {s}\n", .{@errorName(err)});
                std.process.exit(70);
            }
        }
    };

    std.process.exit(exit_code);
}

test {
    _ = @import("cli.zig");
    _ = @import("sysv.zig");
    _ = @import("posix.zig");
    _ = @import("config.zig");
    _ = @import("time.zig");
    _ = @import("proc.zig");
    _ = @import("output.zig");
}

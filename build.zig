const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("securemilter", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    mod.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
    mod.linkSystemLibrary("zmq", .{});

    const tests = b.addTest(.{
        .root_module = mod,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    addLintStep(b);
}

/// Add the shared 400-line source-limit check.
pub fn addLintStep(b: *std.Build) void {
    const lint = b.addSystemCommand(&.{"sh"});
    lint.addFileArg(b.path("tools/check-line-limit.sh"));
    lint.addArg("src");
    lint.addArg(".line-limit-allow");
    if (b.args) |args| lint.addArgs(args);

    // The line count is a property of the working tree, not of any build input,
    // so the result must never be served from cache.
    lint.has_side_effects = true;

    const step = b.step("lint", "Fail on source files over the 400-line limit");
    step.dependOn(&lint.step);
}

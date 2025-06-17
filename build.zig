const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "kzigg",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const bench = b.addExecutable(.{
        .name = "bench",
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe }),
    });

    bench.addLibraryPath(b.path("src"));
    bench.addIncludePath(b.path("blst/bindings"));
    bench.addLibraryPath(b.path("blst"));
    bench.addObjectFile(b.path("blst/libblst.a"));

    lib.linkLibC();
    lib.addIncludePath(b.path("blst/bindings"));
    lib.addLibraryPath(b.path("blst"));
    lib.addObjectFile(b.path("blst/libblst.a"));

    b.installArtifact(lib);
    const install_step = b.addInstallArtifact(bench, .{});
    const build_step = b.step("bench", "Build benchmarks");

    build_step.dependOn(&install_step.step);
    const run_cmd = b.addRunArtifact(bench);
    const run_step = b.step("benchmark", "Run KZG commitment benchmark");

    run_step.dependOn(&run_cmd.step);

    const filter = b.option([]const u8, "test-filter", "Filter for tests");

    const main_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .filter = filter,
    });
    main_tests.linkLibC();
    main_tests.addIncludePath(b.path("blst/bindings"));
    main_tests.addLibraryPath(b.path("blst"));
    main_tests.addObjectFile(b.path("blst/libblst.a"));

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}

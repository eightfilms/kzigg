const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "kzigg",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const bench = b.addExecutable(.{
        .name = "bench",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = .{ .path = "src/bench.zig" },
        .target = target,
        .optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe }),
    });

    bench.addLibraryPath(.{ .path = "src/main.zig" });
    bench.addIncludePath(.{ .path = "blst/bindings" });
    bench.addLibraryPath(.{ .path = "blst" });
    bench.addObjectFile(.{ .path = "blst/libblst.a" });

    lib.linkLibC();
    lib.addIncludePath(.{ .path = "blst/bindings" });
    lib.addLibraryPath(.{ .path = "blst" });
    lib.addObjectFile(.{ .path = "blst/libblst.a" });

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);
    const install_step = b.addInstallArtifact(bench, .{});
    const build_step = b.step("build bench", "Build benchmarks");

    build_step.dependOn(&install_step.step);
    const run_cmd = b.addRunArtifact(bench);
    const run_step = b.step("benchmark", "Run KZG commitment benchmark");

    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const filter = b.option([]const u8, "test-filter", "Filter for tests");

    const main_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
        .filter = filter,
    });
    main_tests.linkLibC();
    main_tests.addIncludePath(.{ .path = "blst/bindings" });
    main_tests.addLibraryPath(.{ .path = "blst" });
    main_tests.addObjectFile(.{ .path = "blst/libblst.a" });

    const run_main_tests = b.addRunArtifact(main_tests);

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build test`
    // This will evaluate the `test` step rather than the default, which is "install".
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}

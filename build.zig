const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const coapz_dep = b.dependency("coapz", .{
        .target = target,
        .optimize = optimize,
    });

    // Library module
    const lib_mod = b.addModule("coapd", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addImport("coapz", coapz_dep.module("coapz"));

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "coapd",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // Examples
    const example_names = [_][]const u8{ "echo", "client_example" };
    for (example_names) |name| {
        const example_mod = b.createModule(.{
            .root_source_file = b.path(
                b.fmt("examples/{s}.zig", .{name}),
            ),
            .target = target,
            .optimize = optimize,
        });
        example_mod.addImport("coapd", lib_mod);
        example_mod.addImport("coapz", coapz_dep.module("coapz"));

        const example_exe = b.addExecutable(.{
            .name = name,
            .root_module = example_mod,
        });
        b.installArtifact(example_exe);
    }

    // Benchmark client
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_mod.addImport("coapz", coapz_dep.module("coapz"));
    bench_mod.addImport("coapd", lib_mod);

    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = bench_mod,
    });
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    if (b.args) |args| {
        run_bench.addArgs(args);
    }
    const bench_step = b.step("bench", "Run benchmark client");
    bench_step.dependOn(&run_bench.step);

    // Tests
    const lib_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_tests.step);

    // Documentation
    const docs = lib.getEmittedDocs();
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs,
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate API reference documentation");
    docs_step.dependOn(&install_docs.step);
}

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
    const example_names = [_][]const u8{"echo"};
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

    // Tests
    const lib_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_tests.step);
}

const std = @import("std");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const KZGTrustedSetupConfig = @import("main.zig").KZGTrustedSetupConfig;
const BYTES_PER_BLOB = @import("main.zig").BYTES_PER_BLOB;
const FIELD_ELEMENTS_PER_BLOB = @import("main.zig").FIELD_ELEMENTS_PER_BLOB;
const Fr = @import("main.zig").Fr;
const frRand = @import("main.zig").frRand;
const bytesFromBlsField = @import("main.zig").bytesFromBlsField;
const commitmentBytesFromBlob = @import("main.zig").commitmentBytesFromBlob;
const computeKzgProofBlob = @import("main.zig").computeKzgProofBlob;
const verifyKzgProofBlobBatch = @import("main.zig").verifyKzgProofBlobBatch;

fn verify() !void {
    var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa_allocator.allocator();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    const n_samples: usize = 16;
    var proofs = try allocator.alloc([48]u8, n_samples);
    defer allocator.free(proofs);
    var commitments = try allocator.alloc([48]u8, n_samples);
    defer allocator.free(commitments);
    var blobs = try ArrayList([BYTES_PER_BLOB]u8).initCapacity(allocator, n_samples);
    defer blobs.deinit();

    for (0..n_samples) |i| {
        var blob = try allocator.alloc(u8, BYTES_PER_BLOB);
        defer allocator.free(blob);
        for (0..FIELD_ELEMENTS_PER_BLOB) |j| {
            const fr: Fr = try frRand();
            @memcpy(blob[j * @sizeOf(Fr) ..][0..@sizeOf(Fr)], &bytesFromBlsField(fr));
        }
        try blobs.append(blob[0..BYTES_PER_BLOB].*);

        const commitment_raw = try commitmentBytesFromBlob(allocator, blob, cfg);
        commitments[i] = commitment_raw;
        const proof_raw = try computeKzgProofBlob(allocator, blob, commitment_raw, cfg);
        proofs[i] = proof_raw;
    }

    var timer = try std.time.Timer.start();
    const n = 16;
    for (0..n) |_| {
        try std.testing.expect(try verifyKzgProofBlobBatch(
            allocator,
            proofs[0..n_samples],
            commitments[0..n_samples],
            blobs.items[0..n_samples],
            cfg,
        ));
    }
    const elapsed = timer.read();
    std.debug.print("Took {} to verify blobs of size {} for {} iterations\n", .{
        std.fmt.fmtDuration(elapsed),
        n_samples,
        n,
    });
    std.debug.print("(Average) {} to verify blobs of size {}\n", .{
        std.fmt.fmtDuration(elapsed / n),
        n_samples,
    });
}

pub fn main() !void {
    try verify();
}

//func benchCommit(scale uint8, b *testing.B) {
//	fs := NewFFTSettings(scale)
//	setupG1, setupG2 := GenerateTestingSetup("1234", uint64(1)<<scale)
//	ks := NewKZGSettings(fs, setupG1, setupG2)
//	setupLagrange, err := ks.FFTG1(setupG1, true)
//	if err != nil {
//		b.Fatal(err)
//	}
//	blob := make([]bls.Fr, uint64(1)<<scale)
//	for i := 0; i < len(blob); i++ {
//		blob[i] = *bls.RandomFr()
//	}
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		bls.LinCombG1(setupLagrange, blob)
//	}
//}

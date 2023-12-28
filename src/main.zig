const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const assert = std.debug.assert;

const blst = @cImport({
    @cInclude("blst.h");
});

const Limb = blst.limb_t;
const Scalar = blst.blst_scalar;
const Fr = blst.blst_fr;
const Fp = blst.blst_fp;
const Fp2 = blst.blst_fp2;
const Fp6 = blst.blst_fp6;
const Fp12 = blst.blst_fp12;
const G1 = blst.blst_p1;
const G2 = blst.blst_p2;
const P1Affine = blst.blst_p1_affine;
const P2Affine = blst.blst_p2_affine;

/// The zero field element.
const FR_ZERO = Fr{ .l = [4]Limb{ 0, 0, 0, 0 } };
/// Adapted from: https://github.com/ethereum/c-kzg-4844/blob/e266280d88f006b23925c5062476b316d5407cb1/src/c_kzg_4844.c#L155
const FR_ONE = Fr{ .l = [4]Limb{
    0x00000001fffffffe,
    0x5884b7fa00034802,
    0x998c4fefecbc4ff5,
    0x1824b159acc5056f,
} };

const G1_IDENTITY: G1 = G1{
    .x = Fp{ .l = [_]Limb{ 0, 0, 0, 0, 0, 0 } },
    .y = Fp{ .l = [_]Limb{ 0, 0, 0, 0, 0, 0 } },
    .z = Fp{ .l = [_]Limb{ 0, 0, 0, 0, 0, 0 } },
};

const FieldError = error{
    BadScalar,
    InvalidUncompressedG1,
    WrongSubgroup,
};

const CHALLENGE_INPUT_SIZE: usize = DOMAIN_STR_LENGTH + 16 + BYTES_PER_BLOB + BYTES_PER_G1_COMPRESSED;

/// Number of field elements in a blob as defined in EIP-4844.
const FIELD_ELEMENTS_PER_BLOB = 4096;

const BYTES_PER_BLOB = @sizeOf(Fr) * FIELD_ELEMENTS_PER_BLOB;

/// The domain separator for the Fiat-Shamir protocol.
const FIAT_SHAMIR_PROTOCOL_DOMAIN = "FSBLOBVERIFY_V1_";

/// The domain separator for a random challenge.
const RANDOM_CHALLENGE_KZG_BATCH_DOMAIN: []const u8 = "RCKZGBATCH___V1_";

/// Length of the domain strings above.
const DOMAIN_STR_LENGTH = 16;

/// Number of bytes for a compressed G1 point.
const BYTES_PER_G1_COMPRESSED: usize = 48;

/// Number of bytes for a compressed G2 point.
const BYTES_PER_G2_COMPRESSED: usize = 96;

/// Number of G1 points per blob.
const TRUSTED_SETUP_NUM_G1_POINTS: usize = FIELD_ELEMENTS_PER_BLOB;

/// Number of G2 points per blob.
const TRUSTED_SETUP_NUM_G2_POINTS: usize = 65;

/// The first 32 roots of unity in the finite field F_r.
/// `SCALE2_ROOT_OF_UNITY[i]` is a 2^i'th root of unity.
///
/// For full details:
/// https://github.com/ethereum/c-kzg-4844/blob/e266280d88f006b23925c5062476b316d5407cb1/src/c_kzg_4844.c#L92-L116
const SCALE2_ROOT_OF_UNITY: [32][4]u64 = [32][4]u64{
    [4]u64{ 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 },
    [4]u64{ 0xffffffff00000000, 0x53bda402fffe5bfe, 0x3339d80809a1d805, 0x73eda753299d7d48 },
    [4]u64{ 0x0001000000000000, 0xec03000276030000, 0x8d51ccce760304d0, 0x0000000000000000 },
    [4]u64{ 0x7228fd3397743f7a, 0xb38b21c28713b700, 0x8c0625cd70d77ce2, 0x345766f603fa66e7 },
    [4]u64{ 0x53ea61d87742bcce, 0x17beb312f20b6f76, 0xdd1c0af834cec32c, 0x20b1ce9140267af9 },
    [4]u64{ 0x360c60997369df4e, 0xbf6e88fb4c38fb8a, 0xb4bcd40e22f55448, 0x50e0903a157988ba },
    [4]u64{ 0x8140d032f0a9ee53, 0x2d967f4be2f95155, 0x14a1e27164d8fdbd, 0x45af6345ec055e4d },
    [4]u64{ 0x5130c2c1660125be, 0x98d0caac87f5713c, 0xb7c68b4d7fdd60d0, 0x6898111413588742 },
    [4]u64{ 0x4935bd2f817f694b, 0x0a0865a899e8deff, 0x6b368121ac0cf4ad, 0x4f9b4098e2e9f12e },
    [4]u64{ 0x4541b8ff2ee0434e, 0xd697168a3a6000fe, 0x39feec240d80689f, 0x095166525526a654 },
    [4]u64{ 0x3c28d666a5c2d854, 0xea437f9626fc085e, 0x8f4de02c0f776af3, 0x325db5c3debf77a1 },
    [4]u64{ 0x4a838b5d59cd79e5, 0x55ea6811be9c622d, 0x09f1ca610a08f166, 0x6d031f1b5c49c834 },
    [4]u64{ 0xe206da11a5d36306, 0x0ad1347b378fbf96, 0xfc3e8acfe0f8245f, 0x564c0a11a0f704f4 },
    [4]u64{ 0x6fdd00bfc78c8967, 0x146b58bc434906ac, 0x2ccddea2972e89ed, 0x485d512737b1da3d },
    [4]u64{ 0x034d2ff22a5ad9e1, 0xae4622f6a9152435, 0xdc86b01c0d477fa6, 0x56624634b500a166 },
    [4]u64{ 0xfbd047e11279bb6e, 0xc8d5f51db3f32699, 0x483405417a0cbe39, 0x3291357ee558b50d },
    [4]u64{ 0xd7118f85cd96b8ad, 0x67a665ae1fcadc91, 0x88f39a78f1aeb578, 0x2155379d12180caa },
    [4]u64{ 0x08692405f3b70f10, 0xcd7f2bd6d0711b7d, 0x473a2eef772c33d6, 0x224262332d8acbf4 },
    [4]u64{ 0x6f421a7d8ef674fb, 0xbb97a3bf30ce40fd, 0x652f717ae1c34bb0, 0x2d3056a530794f01 },
    [4]u64{ 0x194e8c62ecb38d9d, 0xad8e16e84419c750, 0xdf625e80d0adef90, 0x520e587a724a6955 },
    [4]u64{ 0xfece7e0e39898d4b, 0x2f69e02d265e09d9, 0xa57a6e07cb98de4a, 0x03e1c54bcb947035 },
    [4]u64{ 0xcd3979122d3ea03a, 0x46b3105f04db5844, 0xc70d0874b0691d4e, 0x47c8b5817018af4f },
    [4]u64{ 0xc6e7a6ffb08e3363, 0xe08fec7c86389bee, 0xf2d38f10fbb8d1bb, 0x0abe6a5e5abcaa32 },
    [4]u64{ 0x5616c57de0ec9eae, 0xc631ffb2585a72db, 0x5121af06a3b51e3c, 0x73560252aa0655b2 },
    [4]u64{ 0x92cf4deb77bd779c, 0x72cf6a8029b7d7bc, 0x6e0bcd91ee762730, 0x291cf6d68823e687 },
    [4]u64{ 0xce32ef844e11a51e, 0xc0ba12bb3da64ca5, 0x0454dc1edc61a1a3, 0x019fe632fd328739 },
    [4]u64{ 0x531a11a0d2d75182, 0x02c8118402867ddc, 0x116168bffbedc11d, 0x0a0a77a3b1980c0d },
    [4]u64{ 0xe2d0a7869f0319ed, 0xb94f1101b1d7a628, 0xece8ea224f31d25d, 0x23397a9300f8f98b },
    [4]u64{ 0xd7b688830a4f2089, 0x6558e9e3f6ac7b41, 0x99e276b571905a7d, 0x52dd465e2f094256 },
    [4]u64{ 0x474650359d8e211b, 0x84d37b826214abc6, 0x8da40c1ef2bb4598, 0x0c83ea7744bf1bee },
    [4]u64{ 0x694341f608c9dd56, 0xed3a181fabb30adc, 0x1339a815da8b398f, 0x2c6d4e4511657e1e },
    [4]u64{ 0x63e7cb4906ffc93f, 0xf070bb00e28a193d, 0xad1715b02e5713b5, 0x4b5371495990693f },
};

/// A struct to represent data from the trusted setup.
const KZGTrustedSetupConfig = struct {
    allocator: Allocator,
    roots_of_unity: []Fr,
    g1_values: []G1,
    g2_values: []G2,
    max_width: u64,

    const Self = @This();

    /// Loads data from path for a trusted setup.
    fn loadFromFile(allocator: Allocator, trusted_setup_path: []const u8) !Self {
        const fd = try std.fs.cwd().openFile(trusted_setup_path, .{});
        defer fd.close();
        var buf_reader = std.io.bufferedReader(fd.reader());
        var in_stream = buf_reader.reader();

        var num_points_buf: [8]u8 = undefined;

        var num_points_raw = try in_stream.readUntilDelimiterOrEof(&num_points_buf, '\n');
        var num_points = try std.fmt.parseInt(usize, num_points_raw.?, 10);
        assert(num_points == TRUSTED_SETUP_NUM_G1_POINTS);
        var g1_values = try allocator.alloc(G1, num_points);
        errdefer allocator.free(g1_values);

        num_points_raw = try in_stream.readUntilDelimiterOrEof(&num_points_buf, '\n');
        num_points = try std.fmt.parseInt(usize, num_points_raw.?, 10);
        assert(num_points == TRUSTED_SETUP_NUM_G2_POINTS);
        var g2_values = try allocator.alloc(G2, num_points);
        errdefer allocator.free(g2_values);

        for (0..TRUSTED_SETUP_NUM_G1_POINTS) |i| {
            var g1_affine: P1Affine = undefined;
            // Each line consists of 96 bytes of hexstring representing a G1 element
            // and a newline character (1 byte)
            var g1_buf: [97]u8 = undefined;
            _ = try in_stream.readUntilDelimiterOrEof(&g1_buf, '\n');
            // Convert only the hexstring (up to index 96) to bytes (len 48).
            _ = try std.fmt.hexToBytes(&g1_buf, g1_buf[0..96]);

            const blst_err = blst.blst_p1_uncompress(&g1_affine, g1_buf[0..BYTES_PER_G1_COMPRESSED]);

            if (blst_err != blst.BLST_SUCCESS) return error.BlstP1DecodeError;

            blst.blst_p1_from_affine(&g1_values[i], &g1_affine);
        }

        for (0..TRUSTED_SETUP_NUM_G2_POINTS) |i| {
            var g2_affine: P2Affine = undefined;
            // Each line consists of 192 bytes of hexstring representing a G2 element
            // and a newline character (1 byte)
            var g2_buf: [193]u8 = undefined;
            _ = try in_stream.readUntilDelimiterOrEof(&g2_buf, '\n');
            // Convert only the hexstring (up to index 192) to bytes (len 96).
            _ = try std.fmt.hexToBytes(&g2_buf, g2_buf[0..192]);

            const blst_err = blst.blst_p2_uncompress(&g2_affine, g2_buf[0..BYTES_PER_G2_COMPRESSED]);
            if (blst_err != blst.BLST_SUCCESS) return error.BlstP2DecodeError;
            blst.blst_p2_from_affine(&g2_values[i], &g2_affine);
        }

        var max_scale: u6 = 0;
        while ((@as(u64, 1) << max_scale) < TRUSTED_SETUP_NUM_G1_POINTS) {
            max_scale += 1;
        }

        const max_width: u64 = @as(u64, 1) << max_scale;

        // The original C implementation allocates an extra array to store the expanded
        // roots of unity here since it is of length `max_width + 1`, but we can instead
        // allocate that length here, and resize below.
        var roots_of_unity: []Fr = try allocator.alloc(
            Fr,
            max_width + 1,
        );
        try computeRootsOfUnity(&roots_of_unity, max_scale, max_width);
        // Assert to ensure that resizing doesn't fail here.
        assert(allocator.resize(roots_of_unity, max_width));

        try bitReversalPermutation(G1, g1_values, TRUSTED_SETUP_NUM_G1_POINTS);

        return .{
            .allocator = allocator,
            .roots_of_unity = roots_of_unity[0..max_width],
            .g1_values = g1_values,
            .g2_values = g2_values,
            .max_width = max_width,
        };
    }

    fn deinit(self: Self) void {
        self.allocator.free(self.g1_values);
        self.allocator.free(self.g2_values);
        self.allocator.free(self.roots_of_unity);
    }
};
// Subtract two G2 group elements.
pub fn g1Sub(a: G1, b: G1) G1 {
    var b_neg: G1 = b;
    var out: G1 = undefined;

    blst.blst_p1_cneg(&b_neg, true);
    blst.blst_p1_add_or_double(&out, &a, &b_neg);

    return out;
}

pub fn g1Rand() !G1 {
    const len: usize = 32;
    var buf: [len]u8 = undefined;
    try std.os.getrandom(&buf);

    var out: G1 = undefined;
    blst.blst_hash_to_g1(&out, &buf, len, null, 0, null, 0);
    return out;
}
/// Multiply a `G1` group element `g` with a field element `Fr`.
pub fn g1Mul(g: G1, fr: Fr) G1 {
    var scalar: Scalar = undefined;
    var out: G1 = undefined;
    blst.blst_scalar_from_fr(&scalar, &fr);
    blst.blst_p1_mult(&out, &g, &scalar.b, 8 * @sizeOf(Scalar));

    return out;
}

pub fn g2Rand() !G2 {
    const len: usize = 32;
    var buf: [len]u8 = undefined;
    try std.os.getrandom(&buf);

    var out: G2 = undefined;
    blst.blst_hash_to_g2(&out, &buf, len, null, 0, null, 0);
    return out;
}

/// Multiply a `G2` group element `g` with a field element `Fr`.
fn g2Mul(g: G2, fr: Fr) G2 {
    var scalar: Scalar = undefined;
    var out: G2 = undefined;
    blst.blst_scalar_from_fr(&scalar, &fr);
    blst.blst_p2_mult(&out, &g, &scalar.b, 8 * @sizeOf(Scalar));

    return out;
}

// Subtract two G2 group elements.
fn g2Sub(a: G2, b: G2) G2 {
    var b_neg: G2 = b;
    var out: G2 = undefined;

    blst.blst_p2_cneg(&b_neg, true);
    blst.blst_p2_add_or_double(&out, &a, &b_neg);

    return out;
}
/// Naive linear combination of G1 group elements.
///
/// `[coefficients_0]p_0 + [coefficients_1]p_1 + ... + [coefficients_n]p_n` where
/// `n` == `len - 1`.
fn g1LinearCombinationNaive(p: []G1, coefficients: []Fr) G1 {
    assert(p.len == coefficients.len);

    var tmp: G1 = undefined;
    var out = G1_IDENTITY;

    for (coefficients, p) |c, g| {
        tmp = g1Mul(g, c);
        blst.blst_p1_add_or_double(&out, &out, &tmp);
    }

    return out;
}

/// Calculates the linear combination of G1 group elements using Pippenger's
/// algorithm.
///
/// `[coefficients_0]p_0 + [coefficients_1]p_1 + ... + [coefficients_n]p_n` where
/// `n` == `len - 1`.
fn g1LinearCombination(allocator: Allocator, p: []G1, coefficients: []Fr) !G1 {
    assert(p.len == coefficients.len);

    // const out = G1_IDENTITY;
    var out = G1_IDENTITY;

    // For small lengths, we prefer the naive version
    if (p.len < 8) return g1LinearCombinationNaive(p, coefficients);

    const scratch_size: usize = blst.blst_p1s_mult_pippenger_scratch_sizeof(p.len);

    const scratch = try allocator.alloc(Limb, scratch_size);
    defer allocator.free(scratch);

    const p1_affines: []P1Affine = try allocator.alloc(P1Affine, p.len);
    defer allocator.free(p1_affines);
    var scalars = try allocator.alloc(Scalar, p.len);
    defer allocator.free(scalars);

    var p_args = [_:null]?*const G1{@ptrCast(p)};
    blst.blst_p1s_to_affine(
        p1_affines.ptr,
        &p_args,
        p.len,
    );

    // Transform field elements to 256-bit scalars
    for (0..p.len) |i| {
        blst.blst_scalar_from_fr(&scalars[i], &coefficients[i]);
    }

    var scalars_arg = [_:null]?*const u8{@ptrCast(@alignCast(std.mem.asBytes(scalars)))};
    var points_arg = [_:null]?*const P1Affine{@ptrCast(p1_affines)};
    blst.blst_p1s_mult_pippenger(
        &out,
        &points_arg,
        p.len,
        &scalars_arg,
        255,
        scratch.ptr,
    );

    return out;
}

fn hashToBlsField(in: [32]u8) Fr {
    var scalar: Scalar = undefined;
    var fr: Fr = undefined;

    blst.blst_scalar_from_bendian(&scalar, &in);
    blst.blst_fr_from_scalar(&fr, &scalar);

    return fr;
}

fn bytesToBlsField(in: [32]u8) !Fr {
    var scalar: Scalar = undefined;
    var fr: Fr = undefined;

    blst.blst_scalar_from_bendian(&scalar, &in);
    if (!blst.blst_scalar_fr_check(&scalar)) return FieldError.BadScalar;
    blst.blst_fr_from_scalar(&fr, &scalar);

    return fr;
}

/// Serialize a BLS field element into bytes.
fn bytesFromBlsField(fr: Fr) [32]u8 {
    var s: Scalar = undefined;
    var out: [32]u8 = undefined;

    blst.blst_scalar_from_fr(&s, &fr);
    blst.blst_bendian_from_scalar(&out, &s);

    return out;
}

/// Initialize and return a random field element. Useful for tests.
fn frRand() !Fr {
    var buf: [32]u8 = undefined;
    try std.os.getrandom(&buf);

    return hashToBlsField(buf);
}

/// Montgomery batch inversion in finite field.
///
/// This function is NOT in-place; a fresh `out` buffer must be
/// provided.
fn frBatchInverse(out: *[]Fr, a: *[]Fr, len: usize) !void {
    var accumulator = FR_ONE;

    for (0..len) |i| {
        out.*[i] = accumulator;
        blst.blst_fr_mul(&accumulator, &accumulator, &a.*[i]);
    }

    if (std.meta.eql(accumulator, FR_ZERO)) return error.ZeroBatchInverse;

    blst.blst_fr_eucl_inverse(&accumulator, &accumulator);

    for (0..len) |i| {
        blst.blst_fr_mul(
            &out.*[len - 1 - i],
            &out.*[len - 1 - i],
            &accumulator,
        );
        blst.blst_fr_mul(
            &accumulator,
            &accumulator,
            &a.*[len - 1 - i],
        );
    }
}
/// Divide a field element by another.
pub fn frDiv(a: Fr, b: Fr) !Fr {
    var tmp: Fr = undefined;
    var out: Fr = undefined;

    blst.blst_fr_eucl_inverse(&tmp, &b);
    blst.blst_fr_mul(&out, &a, &tmp);

    return out;
}

/// Exponentiation of a field element; uses square and multiply for
/// log(n) performance.
pub fn frPow(a: Fr, n: u64) !Fr {
    var tmp: Fr = a;
    var out: Fr = FR_ONE;
    var m = n;

    while (true) {
        if (m & 1 > 0)
            blst.blst_fr_mul(&out, &out, &tmp);

        m >>= 1;
        if (m == 0) break;
        blst.blst_fr_sqr(&tmp, &tmp);
    }

    return out;
}
/// Reorder an array in reverse bit order of its indices.
fn bitReversalPermutation(comptime T: type, values: []T, n: usize) !void {
    if (!std.math.isPowerOfTwo(values.len)) return error.BitReversal;

    const unused_bit_len = 32 - std.math.log2(n);

    for (0..n) |i| {
        const r = std.math.shr(u64, reverseBits(@intCast(i)), unused_bit_len);

        if (r > i) std.mem.swap(T, &values[i], &values[r]);
    }
}

/// Generate powers of a root of unity in the field.
fn expandRootOfUnity(expanded_roots: *[]Fr, root: Fr, width: u64) !void {
    expanded_roots.*[0] = FR_ONE;
    expanded_roots.*[1] = root;

    var i: usize = 2;
    while (i <= width) {
        blst.blst_fr_mul(&expanded_roots.*[i], &expanded_roots.*[i - 1], &root);

        if (std.meta.eql(expanded_roots.*[i], FR_ONE)) break;
        i += 1;
    }

    if (i != width or (!std.meta.eql(expanded_roots.*[width], FR_ONE))) return error.RootsOfUnityExpansionFailure;
}

/// Reverse bit order in a 32-bit integer.
fn reverseBits(n: u32) u32 {
    var num = n;
    var result: u32 = 0;
    for (0..32) |_| {
        result <<= 1;
        result |= (num & 1);
        num >>= 1;
    }

    return result;
}

/// Expands and initializes the roots of unity.
fn computeRootsOfUnity(roots: *[]Fr, max_scale: u6, max_width: u64) !void {
    var root_of_unity: Fr = undefined;
    blst.blst_fr_from_uint64(&root_of_unity, &SCALE2_ROOT_OF_UNITY[max_scale]);

    try expandRootOfUnity(roots, root_of_unity, max_width);

    // Since we reused the roots slice for both expanded roots as well as the
    // actual returned roots, we take a slice up till `roots.len - 1` here for
    // the bit reversal permutation.
    try bitReversalPermutation(Fr, roots.*[0 .. roots.len - 1], TRUSTED_SETUP_NUM_G1_POINTS);
}

const Polynomial = struct {
    const Self = @This();

    allocator: Allocator,
    evals: []Fr,

    /// Initializes a Polynomial (array of field elements) from an
    /// array of bytes.
    pub fn fromBlob(allocator: Allocator, blob: []u8) !Self {
        const evals = try allocator.alloc(Fr, FIELD_ELEMENTS_PER_BLOB);
        errdefer allocator.free(evals);
        for (0..FIELD_ELEMENTS_PER_BLOB) |i| {
            evals[i] = try bytesToBlsField(blob[i * @sizeOf(Fr) ..][0..@sizeOf(Fr)].*);
        }

        return .{
            .allocator = allocator,
            .evals = evals,
        };
    }

    /// Evaluate a polynomial (in evaluation form) at a given point `x`.
    pub fn evalAt(self: Self, x: Fr, s: KZGTrustedSetupConfig) !Fr {
        var inverses: []Fr = try self.allocator.alloc(Fr, FIELD_ELEMENTS_PER_BLOB);
        defer self.allocator.free(inverses);
        var inverses_in: []Fr = try self.allocator.alloc(Fr, FIELD_ELEMENTS_PER_BLOB);
        defer self.allocator.free(inverses_in);
        for (0..FIELD_ELEMENTS_PER_BLOB) |i| {
            // Return result directly if point to evaluate is
            // one of the evaluation points by which the polynomial
            // is given
            if (std.meta.eql(x, s.roots_of_unity[i])) return self.evals[i];

            blst.blst_fr_sub(&inverses_in[i], &x, &s.roots_of_unity[i]);
        }

        try frBatchInverse(&inverses, &inverses_in, FIELD_ELEMENTS_PER_BLOB);

        var out = FR_ZERO;
        var tmp: Fr = undefined;
        for (0..FIELD_ELEMENTS_PER_BLOB) |i| {
            blst.blst_fr_mul(&tmp, &inverses[i], &s.roots_of_unity[i]);
            blst.blst_fr_mul(&tmp, &tmp, &self.evals[i]);
            blst.blst_fr_add(&out, &out, &tmp);
        }

        blst.blst_fr_from_uint64(&tmp, &[4]Limb{ FIELD_ELEMENTS_PER_BLOB, 0, 0, 0 });
        out = try frDiv(out, tmp);
        tmp = try frPow(x, FIELD_ELEMENTS_PER_BLOB);
        blst.blst_fr_sub(&tmp, &tmp, &FR_ONE);
        blst.blst_fr_mul(&out, &out, &tmp);

        return out;
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.evals);
    }
};

fn validateKzgG1(bytes: [48]u8) !G1 {
    var p1_affine: P1Affine = undefined;
    var out: G1 = undefined;

    if (blst.blst_p1_uncompress(&p1_affine, &bytes) != blst.BLST_SUCCESS)
        return FieldError.InvalidUncompressedG1;

    blst.blst_p1_from_affine(&out, &p1_affine);

    if (!blst.blst_p1_in_g1(&out)) return FieldError.WrongSubgroup;

    return out;
}

/// Convert untrusted bytes into a trusted and validated G1 point.
/// This can be used to convert bytes to a commitment or proof.
fn g1FromBytes(raw_commitment: [48]u8) !G1 {
    return try validateKzgG1(raw_commitment);
}

/// Compute a KZG commitment from a polynomial. The resulting
/// commitment is a compressed G1 point, 48 bytes in size.
fn commitmentBytesFromBlob(
    allocator: Allocator,
    blob: []u8,
    cfg: KZGTrustedSetupConfig,
) ![48]u8 {
    var out: [48]u8 = undefined;
    const p = try Polynomial.fromBlob(allocator, blob);
    defer p.deinit();
    const c = try commitmentFromPolynomial(allocator, cfg.g1_values, p);
    blst.blst_p1_compress(&out, &c);

    return out;
}

/// Compute a KZG commitment from a polynomial. The resulting
/// commitment is just a G1 point, 48 bytes in size.
fn commitmentFromPolynomial(allocator: Allocator, g1_values: []G1, p: Polynomial) !G1 {
    return try g1LinearCombination(allocator, g1_values, p.evals);
}

/// Compute KZG proof for a polynomial in Lagrange form at position z.
fn computeKzgProofLagrange(
    allocator: Allocator,
    blob: []u8,
    z_raw: [32]u8,
    cfg: KZGTrustedSetupConfig,
) !struct { [48]u8, [32]u8 } {
    const polynomial = try Polynomial.fromBlob(allocator, blob);
    defer polynomial.deinit();
    const z = try bytesToBlsField(z_raw);
    return try computeKzgProof(allocator, polynomial, z, cfg);
}

fn computeKzgProofBlob(
    allocator: Allocator,
    blob: []u8,
    commitment_raw: [48]u8,
    cfg: KZGTrustedSetupConfig,
) ![48]u8 {
    const commitment: G1 = try g1FromBytes(commitment_raw);
    const polynomial = try Polynomial.fromBlob(allocator, blob);
    defer polynomial.deinit();

    const challenge = try computeChallenge(blob, commitment);

    const proof_raw, _ = try computeKzgProof(allocator, polynomial, challenge, cfg);

    return proof_raw;
}

fn computeKzgProof(
    allocator: Allocator,
    polynomial: Polynomial,
    z: Fr,
    cfg: KZGTrustedSetupConfig,
) !struct { [48]u8, [32]u8 } {
    var inverses: []Fr = try allocator.alloc(Fr, FIELD_ELEMENTS_PER_BLOB);
    defer allocator.free(inverses);
    var inverses_in: []Fr = try allocator.alloc(Fr, FIELD_ELEMENTS_PER_BLOB);
    defer allocator.free(inverses_in);

    var m: u64 = 0;
    const y = try polynomial.evalAt(z, cfg);
    var q = Polynomial{
        .evals = undefined,
        .allocator = allocator,
    };
    q.evals = try allocator.alloc(Fr, FIELD_ELEMENTS_PER_BLOB);

    for (0..FIELD_ELEMENTS_PER_BLOB) |i| {
        if (std.meta.eql(z, cfg.roots_of_unity[i])) {
            m = i + 1;
            inverses_in[i] = FR_ONE;
            continue;
        }

        // (p_i - y) / (ω_i - z)
        blst.blst_fr_sub(&q.evals[i], &polynomial.evals[i], &y);
        blst.blst_fr_sub(&inverses_in[i], &cfg.roots_of_unity[i], &z);
    }
    defer q.deinit();

    try frBatchInverse(
        &inverses,
        &inverses_in,
        FIELD_ELEMENTS_PER_BLOB,
    );

    for (0..FIELD_ELEMENTS_PER_BLOB) |i| {
        blst.blst_fr_mul(&q.evals[i], &q.evals[i], &inverses[i]);
    }

    // w_{m-1} == z
    if (m != 0) {
        var tmp: Fr = undefined;
        m -= 1;
        q.evals[m] = FR_ZERO;

        for (0..FIELD_ELEMENTS_PER_BLOB) |i| {
            if (i == m) continue;
            blst.blst_fr_sub(&tmp, &z, &cfg.roots_of_unity[i]);
            blst.blst_fr_mul(&inverses_in[i], &tmp, &z);
        }
        try frBatchInverse(
            &inverses,
            &inverses_in,
            FIELD_ELEMENTS_PER_BLOB,
        );

        for (0..FIELD_ELEMENTS_PER_BLOB) |i| {
            if (i == m) continue;
            // Build numerator: w_i * (p_i - y)
            blst.blst_fr_sub(&tmp, &polynomial.evals[i], &y);
            blst.blst_fr_mul(&tmp, &tmp, &cfg.roots_of_unity[i]);

            // Do division: w_i * (p_i - y)
            blst.blst_fr_mul(&tmp, &tmp, &inverses[i]);
            blst.blst_fr_add(&q.evals[m], &q.evals[m], &tmp);
        }
    }

    const g1 = try g1LinearCombination(allocator, cfg.g1_values, q.evals);
    var proof_raw: [48]u8 = undefined;
    blst.blst_p1_compress(&proof_raw, &g1);

    const y_raw = bytesFromBlsField(y);
    return .{ proof_raw, y_raw };
}

/// Compute the Fiat-Shamir challenge required to verify `blob` and `commitment`.
///
/// The challenge is a field element.
fn computeChallenge(blob: []u8, commitment: G1) !Fr {
    var eval_challenge: [32]u8 = undefined;
    var bytes: [CHALLENGE_INPUT_SIZE]u8 = undefined;

    var offset: usize = 0;

    @memcpy(bytes[offset .. offset + DOMAIN_STR_LENGTH], FIAT_SHAMIR_PROTOCOL_DOMAIN);
    offset += DOMAIN_STR_LENGTH;
    @memset(bytes[offset .. offset + @sizeOf(u64)], 0);
    offset += @sizeOf(u64);
    @memcpy(bytes[offset .. offset + @sizeOf(u64)], std.mem.asBytes(&@as(u64, FIELD_ELEMENTS_PER_BLOB)));
    offset += @sizeOf(u64);
    @memcpy(bytes[offset .. offset + BYTES_PER_BLOB], blob);
    offset += BYTES_PER_BLOB;

    blst.blst_p1_compress(bytes[offset .. offset + BYTES_PER_G1_COMPRESSED].ptr, &commitment);
    offset += BYTES_PER_G1_COMPRESSED;

    assert(offset == CHALLENGE_INPUT_SIZE);

    blst.blst_sha256(&eval_challenge, &bytes, CHALLENGE_INPUT_SIZE);
    return hashToBlsField(eval_challenge);
}

/// Verify a KZG proof with the claim that `p(z) == y`.
fn verifyKzgProof(
    proof: G1,
    commitment: G1,
    z: Fr,
    y: Fr,
    cfg: KZGTrustedSetupConfig,
) !bool {
    const p2_generator: *const blst.blst_p2 = blst.blst_p2_generator();
    const p1_generator: *const blst.blst_p1 = blst.blst_p1_generator();
    // X - z
    const x_g2 = g2Mul(p2_generator.*, z);
    const x_minus_z = g2Sub(cfg.g2_values[1], x_g2);

    // P - z
    const y_g1 = g1Mul(p1_generator.*, y);
    const p_minus_y = g1Sub(commitment, y_g1);

    // Verify: P - y = Q * (X - z)
    return verify_pairings(
        p_minus_y,
        p2_generator.*,
        proof,
        x_minus_z,
    );
}

/// Verify a given blob and its proof against its commitment.
fn verifyKzgProofBlob(
    allocator: Allocator,
    blob: []u8,
    proof_raw: [48]u8,
    commitment_raw: [48]u8,
    cfg: KZGTrustedSetupConfig,
) !bool {
    const commitment: G1 = try g1FromBytes(commitment_raw);
    const polynomial: Polynomial = try Polynomial.fromBlob(allocator, blob);
    defer polynomial.deinit();
    const proof: G1 = try g1FromBytes(proof_raw);

    const challenge = try computeChallenge(blob, commitment);

    const y = try polynomial.evalAt(challenge, cfg);

    return verifyKzgProof(proof, commitment, challenge, y, cfg);
}

/// Given x, compute and return [ x^0, x^1, ..., x^n-1 ].
fn computePowers(out: []Fr, x: Fr) void {
    var current_power: Fr = FR_ONE;
    for (0..out.len) |i| {
        out[i] = current_power;
        blst.blst_fr_mul(&current_power, &current_power, &x);
    }
}

/// Compute random linear combination challenge scalars for batch verification.
fn computeRPowers(out: []Fr, allocator: Allocator, commitments: []G1, zs: []Fr, ys: []Fr, proofs: []G1) !void {
    const size: usize = DOMAIN_STR_LENGTH + @sizeOf(u64) + @sizeOf(u64) +
        (commitments.len * (BYTES_PER_G1_COMPRESSED + 2 * @sizeOf(Fr) + BYTES_PER_G1_COMPRESSED));

    var bytes = try ArrayList(u8).initCapacity(allocator, size);

    bytes.appendSliceAssumeCapacity(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN);
    bytes.appendSliceAssumeCapacity(std.mem.asBytes(&@as(u64, FIELD_ELEMENTS_PER_BLOB)));
    bytes.appendSliceAssumeCapacity(std.mem.asBytes(&@as(u64, commitments.len)));

    for (0..commitments.len) |i| {
        var commitment_raw: [48]u8 = undefined;
        var proof_raw: [48]u8 = undefined;
        const z_raw = bytesFromBlsField(zs[i]);
        const y_raw = bytesFromBlsField(ys[i]);

        blst.blst_p1_compress(&commitment_raw, &commitments[i]);
        bytes.appendSliceAssumeCapacity(&commitment_raw);
        bytes.appendSliceAssumeCapacity(&z_raw);
        bytes.appendSliceAssumeCapacity(&y_raw);

        blst.blst_p1_compress(&proof_raw, &proofs[i]);
        bytes.appendSliceAssumeCapacity(&proof_raw);
    }

    var r_bytes: [32]u8 = undefined;
    blst.blst_sha256(&r_bytes, bytes.items.ptr, size);
    bytes.deinit();
    const r = hashToBlsField(r_bytes);

    computePowers(out, r);
}

/// Verify that a list of provided commitments attest to a
/// list of blobs and accompanying blob KZG proofs.
fn verifyKzgProofBlobBatch(
    allocator: Allocator,
    proofs_raw: [][48]u8,
    commitments_raw: [][48]u8,
    blobs_raw: [][BYTES_PER_BLOB]u8,
    cfg: KZGTrustedSetupConfig,
) !bool {
    assert(blobs_raw.len == commitments_raw.len);
    assert(commitments_raw.len == proofs_raw.len);
    const n = commitments_raw.len;

    var commitments = try allocator.alloc(G1, n);
    defer allocator.free(commitments);
    var proofs = try allocator.alloc(G1, n);
    defer allocator.free(proofs);
    var challenges = try allocator.alloc(Fr, n);
    defer allocator.free(challenges);
    var ys = try allocator.alloc(Fr, n);
    defer allocator.free(ys);

    for (0..n) |i| {
        commitments[i] = try g1FromBytes(commitments_raw[i]);
        var polynomial = try Polynomial.fromBlob(allocator, &blobs_raw[i]);
        defer polynomial.deinit();

        challenges[i] = try computeChallenge(&blobs_raw[i], commitments[i]);
        ys[i] = try polynomial.evalAt(challenges[i], cfg);

        proofs[i] = try g1FromBytes(proofs_raw[i]);
    }

    var c_minus_ys = try allocator.alloc(G1, n);
    defer allocator.free(c_minus_ys);
    var r_times_z = try allocator.alloc(Fr, n);
    defer allocator.free(r_times_z);

    var r_powers = try allocator.alloc(Fr, n);
    defer allocator.free(r_powers);
    try computeRPowers(r_powers, allocator, commitments, challenges, ys, proofs);

    const proof_lc = g1LinearCombinationNaive(proofs, r_powers);

    for (0..n) |i| {
        const p1 = blst.blst_p1_generator();
        const ys_encrypted = g1Mul(p1.*, ys[i]);
        c_minus_ys[i] = g1Sub(commitments[i], ys_encrypted);
        blst.blst_fr_mul(&r_times_z[i], &r_powers[i], &challenges[i]);
    }

    var proof_z_lc = g1LinearCombinationNaive(proofs, r_times_z);
    var c_minus_ys_lc = g1LinearCombinationNaive(c_minus_ys, r_powers);
    var rhs_g1: G1 = undefined;
    blst.blst_p1_add_or_double(&rhs_g1, &c_minus_ys_lc, &proof_z_lc);

    const p2 = blst.blst_p2_generator();
    return verify_pairings(proof_lc, cfg.g2_values[1], rhs_g1, p2.*);
}

/// Perform pairings and test if `e(a1, a2) == e(b1, b2)`.
fn verify_pairings(a1: G1, a2: G2, b1: G1, b2: G2) bool {
    var a1_neg: G1 = a1;
    var aa1: P1Affine = undefined;
    var bb1: P1Affine = undefined;

    var aa2: P2Affine = undefined;
    var bb2: P2Affine = undefined;

    var loop0: Fp12 = undefined;
    var loop1: Fp12 = undefined;
    var gt_point: Fp12 = undefined;

    blst.blst_p1_cneg(&a1_neg, true);

    blst.blst_p1_to_affine(&aa1, &a1_neg);
    blst.blst_p1_to_affine(&bb1, &b1);
    blst.blst_p2_to_affine(&aa2, &a2);
    blst.blst_p2_to_affine(&bb2, &b2);

    blst.blst_miller_loop(&loop0, &aa2, &aa1);
    blst.blst_miller_loop(&loop1, &bb2, &bb1);

    blst.blst_fp12_mul(&gt_point, &loop0, &loop1);
    blst.blst_final_exp(&gt_point, &gt_point);

    return blst.blst_fp12_is_one(&gt_point);
}

test "Fr: div operations" {
    const ONE: Fr = @bitCast(FR_ONE);
    // Divide by one is self.
    for (0..100) |_| {
        const a = try frRand();
        const out = try frDiv(a, ONE);
        try std.testing.expectEqual(out, a);
    }

    // Divide by self is one.
    for (0..100) |_| {
        const a = try frRand();
        const b = a;
        const out = try frDiv(a, b);
        try std.testing.expectEqual(out, ONE);
    }
}

test "Polynomial: test evaluate constant polynomial" {
    const c = try frRand();
    const x = try frRand();

    const allocator = std.testing.allocator;

    const evals = try allocator.alloc(Fr, FIELD_ELEMENTS_PER_BLOB);
    for (0..FIELD_ELEMENTS_PER_BLOB) |i| evals[i] = c;
    var p = Polynomial{
        .evals = evals,
        .allocator = allocator,
    };
    defer p.deinit();

    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();
    const y = try p.evalAt(x, cfg);

    try std.testing.expectEqual(c, y);
}

test "Polynomial: test evaluate constant polynomial in range" {
    const c = try frRand();
    const allocator = std.testing.allocator;

    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    const x = cfg.roots_of_unity[123];

    const evals = try allocator.alloc(Fr, FIELD_ELEMENTS_PER_BLOB);
    for (0..FIELD_ELEMENTS_PER_BLOB) |i| evals[i] = c;

    const p = Polynomial{
        .evals = evals,
        .allocator = allocator,
    };
    defer p.deinit();

    const y = try p.evalAt(x, cfg);

    try std.testing.expectEqual(c, y);
}

test "RootsOfUnity: succeeds with root of unity" {
    var root: Fr = undefined;
    blst.blst_fr_from_uint64(&root, &SCALE2_ROOT_OF_UNITY[8]);

    const allocator = std.testing.allocator;
    var expanded = try allocator.alloc(Fr, 257);
    defer allocator.free(expanded);
    _ = try expandRootOfUnity(&expanded, root, 256);
}

test "RootsOfUnity: fails with not root of unity" {
    var root: Fr = undefined;
    blst.blst_fr_from_uint64(&root, &[4]Limb{ 0, 0, 0, 3 });

    const allocator = std.testing.allocator;
    var expanded = try allocator.alloc(Fr, 257);
    defer allocator.free(expanded);
    try std.testing.expectError(error.RootsOfUnityExpansionFailure, expandRootOfUnity(&expanded, root, 256));
}

test "RootsOfUnity: fails with wrong root of unity" {
    var root: Fr = undefined;
    blst.blst_fr_from_uint64(&root, &SCALE2_ROOT_OF_UNITY[7]);

    const allocator = std.testing.allocator;
    var expanded = try allocator.alloc(Fr, 257);
    defer allocator.free(expanded);
    try std.testing.expectError(error.RootsOfUnityExpansionFailure, expandRootOfUnity(&expanded, root, 256));
}

test "FrBatchInverse: consistency" {
    const allocator = std.testing.allocator;
    var a = try allocator.alloc(Fr, 32);
    defer allocator.free(a);
    var expected_inverses = try allocator.alloc(Fr, 32);
    defer allocator.free(expected_inverses);
    var batch_inverses = try allocator.alloc(Fr, 32);
    defer allocator.free(batch_inverses);

    for (0..32) |i| {
        a[i] = try frRand();
        blst.blst_fr_eucl_inverse(&expected_inverses[i], &a[i]);
    }

    try frBatchInverse(&batch_inverses, &a, 32);
    for (0..32) |i| {
        try std.testing.expect(std.meta.eql(expected_inverses[i], batch_inverses[i]));
    }
}

test "FrBatchInverse: zero error" {
    const allocator = std.testing.allocator;

    var a = try allocator.alloc(Fr, 32);
    defer allocator.free(a);

    for (0..32) |i| a[i] = FR_ZERO;

    var batch_inverses = try allocator.alloc(Fr, 32);
    defer allocator.free(batch_inverses);

    try std.testing.expectError(error.ZeroBatchInverse, frBatchInverse(&batch_inverses, &a, 32));
}

test "ReverseBits: round trip" {
    const original = std.crypto.random.int(u32);

    const reversed = reverseBits(original);
    const reversed_reversed = reverseBits(reversed);

    try std.testing.expectEqual(reversed_reversed, original);
}

test "ReverseBits: all" {
    // all bits 0
    {
        const original = 0;
        const reversed = 0;
        try std.testing.expectEqual(reverseBits(original), reversed);
    }
    // Some bits 1
    {
        const original = 2826829826;
        const reversed = 1073774101;
        try std.testing.expectEqual(reverseBits(original), reversed);
    }
    // All bits 1
    {
        const original = std.math.maxInt(u32);
        const reversed = std.math.maxInt(u32);
        try std.testing.expectEqual(reverseBits(original), reversed);
    }
}

test "BitReversalPermutation: round trip" {
    const n = std.crypto.random.int(u32);
    const allocator = std.testing.allocator;
    const original = try allocator.alloc(u32, 128);
    defer allocator.free(original);

    for (0..128) |i| original[i] = n;
    const reversed_reversed = try allocator.dupe(u32, original);
    defer allocator.free(reversed_reversed);

    try bitReversalPermutation(u32, reversed_reversed, reversed_reversed.len);
    try bitReversalPermutation(u32, reversed_reversed, reversed_reversed.len);

    try std.testing.expectEqualSlices(u32, original, reversed_reversed);
}

test "BitReversalPermutation: coset structure" {
    const allocator = std.testing.allocator;
    const original = try allocator.alloc(u32, 256);
    defer allocator.free(original);

    for (0..256) |i| {
        original[i] = @intCast(i % 16);
    }
    const reversed_reversed = try allocator.dupe(u32, original);
    defer allocator.free(reversed_reversed);

    try bitReversalPermutation(u32, reversed_reversed, reversed_reversed.len);

    for (0..16) |i| {
        for (1..16) |j| {
            try std.testing.expectEqual(reversed_reversed[16 * i], reversed_reversed[16 * i + j]);
        }
    }
}
test "g1LinearCombination: consistency" {
    var naive_out = G1_IDENTITY;

    const allocator = std.testing.allocator;
    var points = try allocator.alloc(G1, 128);
    defer allocator.free(points);
    var scalars = try allocator.alloc(Fr, 128);
    defer allocator.free(scalars);

    for (0..128) |i| {
        scalars[i] = try frRand();
        points[i] = try g1Rand();
    }

    naive_out = g1LinearCombinationNaive(points, scalars);
    const fast_out = try g1LinearCombination(allocator, points, scalars);

    try std.testing.expect(blst.blst_p1_is_equal(&naive_out, &fast_out));
}

test "Trusted setup" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();
}

test "VerifyPairings: good pairing" {
    const s: Fr = try frRand();

    const g1: G1 = try g1Rand();
    const g2: G2 = try g2Rand();
    const g1_mul_out = g1Mul(g1, s);
    const g2_mul_out = g2Mul(g2, s);

    try std.testing.expect(verify_pairings(g1, g2_mul_out, g1_mul_out, g2));
}

test "VerifyPairings: bad pairing" {
    var s: Fr = try frRand();
    var s_plus_one: Fr = undefined;
    blst.blst_fr_add(&s_plus_one, &s, &FR_ONE);

    const g1: G1 = try g1Rand();
    const g2: G2 = try g2Rand();
    const g1_mul_out = g1Mul(g1, s);
    const g2_mul_out = g2Mul(g2, s_plus_one);

    try std.testing.expect(!verify_pairings(g1, g2_mul_out, g1_mul_out, g2));
}

test "computeKzgProof: succeeds expected proof" {
    var fe: [32]u8 = undefined;
    var input: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fe, "69386e69dbae0357b399b8d645a57a3062dfbe00bd8e97170b9bdd6bc6168a13");
    _ = try std.fmt.hexToBytes(&input, "03ea4fb841b4f9e01aa917c5e40dbd67efb4b8d4d9052069595f0647feba320d");

    var blob: [BYTES_PER_BLOB]u8 = [_]u8{0} ** BYTES_PER_BLOB;
    @memcpy(blob[0..32], &fe);

    const allocator = std.testing.allocator;

    const s = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer s.deinit();
    const out, _ = try computeKzgProofLagrange(allocator, &blob, input, s);

    const expected_hex = "b21f8f9b85e52fd9c4a6d4fb4e9a27ebdc5a09c3f5ca17f6bcd85c26f04953b0e6925607aaebed1087e5cc2fe4b2b356";
    var expected: [expected_hex.len / 2]u8 = undefined;
    const proof = try std.fmt.hexToBytes(&expected, expected_hex);
    _ = out;

    try std.testing.expectEqualSlices(u8, &expected, proof);
}

test "computeKzgProofBlob: commitment not in g1" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    var commitment_raw: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&commitment_raw, "8123456789abcdef0123456789abcdef0123456789abcdef8123456789abcdef0123456789abcdef0123456789abcdef");

    var blob = try randBlob();

    try std.testing.expectError(FieldError.WrongSubgroup, computeKzgProofBlob(allocator, &blob, commitment_raw, cfg));
}

test "compute and verify: succeeds round trip" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    var blob = try randBlob();
    var p = try Polynomial.fromBlob(allocator, &blob);
    defer p.deinit();

    const commitment_raw = try commitmentBytesFromBlob(allocator, &blob, cfg);
    const z = try frRand();
    const y = try p.evalAt(z, cfg);
    const z_raw = bytesFromBlsField(z);

    const proof_raw, _ = try computeKzgProofLagrange(allocator, &blob, z_raw, cfg);

    const commitment = try g1FromBytes(commitment_raw);
    const proof = try g1FromBytes(proof_raw);
    try std.testing.expect(try verifyKzgProof(proof, commitment, z, y, cfg));
}

test "compute and verify: succeeds within domain" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    for (cfg.roots_of_unity[0..25]) |z| {
        var blob = try randBlob();
        var p = try Polynomial.fromBlob(allocator, &blob);
        defer p.deinit();

        const commitment_bytes = try commitmentBytesFromBlob(allocator, &blob, cfg);
        const y = try p.evalAt(z, cfg);

        const proof_raw, _ = try computeKzgProofLagrange(allocator, &blob, bytesFromBlsField(z), cfg);

        const proof = try g1FromBytes(proof_raw);
        const commitment = try g1FromBytes(commitment_bytes);
        try std.testing.expect(try verifyKzgProof(proof, commitment, z, y, cfg));
    }
}

test "compute and verify: fails incorrect proof" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    var blob = try randBlob();
    var p = try Polynomial.fromBlob(allocator, &blob);
    defer p.deinit();

    const commitment_raw = try commitmentBytesFromBlob(allocator, &blob, cfg);
    const commitment = try g1FromBytes(commitment_raw);
    const z = try frRand();

    const z_raw = bytesFromBlsField(z);
    const proof_raw, const y_raw = try computeKzgProofLagrange(allocator, &blob, z_raw, cfg);
    const y = try bytesToBlsField(y_raw);
    var proof = try g1FromBytes(proof_raw);

    // Verifying should be OK here.
    try std.testing.expect(try verifyKzgProof(proof, commitment, z, y, cfg));
    // Change the proof to make final verification fail.
    var proof_g1: G1 = try g1FromBytes(proof_raw);
    blst.blst_p1_add(&proof_g1, &proof_g1, blst.blst_p1_generator());
    proof_raw = undefined;
    blst.blst_p1_compress(&proof_raw, &proof_g1);
    proof = try g1FromBytes(proof_raw);

    try std.testing.expect(!try verifyKzgProof(proof, commitment, z, y, cfg));
}

test "compute and verify blob: round trip" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    var blob = try randBlob();

    const commitment_raw = try commitmentBytesFromBlob(allocator, &blob, cfg);
    const proof_raw = try computeKzgProofBlob(allocator, &blob, commitment_raw, cfg);

    try std.testing.expect(try verifyKzgProofBlob(allocator, &blob, proof_raw, commitment_raw, cfg));
}

test "compute and verify blob: incorrect proof" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    var blob = try randBlob();

    const commitment_raw = try commitmentBytesFromBlob(allocator, &blob, cfg);
    var proof_raw = try computeKzgProofBlob(allocator, &blob, commitment_raw, cfg);
    var proof = try g1FromBytes(proof_raw);
    // Verifying should be OK here.
    try std.testing.expect(try verifyKzgProofBlob(allocator, &blob, proof_raw, commitment_raw, cfg));
    // Change the proof to make final verification fail.
    var proof_g1: G1 = try g1FromBytes(proof_raw);
    blst.blst_p1_add(&proof_g1, &proof_g1, blst.blst_p1_generator());
    proof_raw = undefined;
    blst.blst_p1_compress(&proof_raw, &proof_g1);
    proof = try g1FromBytes(proof_raw);

    try std.testing.expect(!try verifyKzgProofBlob(allocator, &blob, proof_raw, commitment_raw, cfg));
}

fn randBlob() ![BYTES_PER_BLOB]u8 {
    var blob: [BYTES_PER_BLOB]u8 = undefined;
    for (0..FIELD_ELEMENTS_PER_BLOB) |i| {
        const fr: Fr = try frRand();
        @memcpy(blob[i * @sizeOf(Fr) ..][0..@sizeOf(Fr)], &bytesFromBlsField(fr));
    }
    return blob;
}

test "verifyKzgProofBlob: proof not in g1" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    var proof_raw: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&proof_raw, "8123456789abcdef0123456789abcdef0123456789abcdef8123456789abcdef0123456789abcdef0123456789abcdef");

    var blob = try randBlob();
    const commitment_raw = try commitmentBytesFromBlob(allocator, &blob, cfg);

    try std.testing.expectError(FieldError.WrongSubgroup, verifyKzgProofBlob(allocator, &blob, proof_raw, commitment_raw, cfg));
}

test "verifyKzgProofBlob: commitment not in g1" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    var commitment_raw_bad: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&commitment_raw_bad, "8123456789abcdef0123456789abcdef0123456789abcdef8123456789abcdef0123456789abcdef0123456789abcdef");

    var blob = try randBlob();
    const commitment_raw_valid = try commitmentBytesFromBlob(allocator, &blob, cfg);
    const proof_raw = try computeKzgProofBlob(allocator, &blob, commitment_raw_valid, cfg);

    try std.testing.expectError(FieldError.WrongSubgroup, verifyKzgProofBlob(allocator, &blob, proof_raw, commitment_raw_bad, cfg));
}

test "verifyKzgProofBlob: invalid blob" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    var fr: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fr, "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

    var blob = [_]u8{0} ** BYTES_PER_BLOB;
    @memcpy(blob[0..@sizeOf(Fr)], &fr);

    const len: usize = BYTES_PER_G1_COMPRESSED;
    var commitment_raw: [len]u8 = undefined;
    var proof_raw: [len]u8 = undefined;
    try std.os.getrandom(&commitment_raw);
    try std.os.getrandom(&proof_raw);

    try std.testing.expectError(FieldError.InvalidUncompressedG1, verifyKzgProofBlob(allocator, &blob, proof_raw, commitment_raw, cfg));
}

test "verifyKzgProofBlobBatch: round trip" {
    const allocator = std.testing.allocator;
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

    for (0..n_samples) |n| {
        try std.testing.expect(try verifyKzgProofBlobBatch(
            allocator,
            proofs[0..n],
            commitments[0..n],
            blobs.items[0..n],
            cfg,
        ));
    }
}

test "verifyKzgProofBlobBatch: incorrect proof" {
    const allocator = std.testing.allocator;
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

    // Randomly overwrite a proof
    proofs[1] = proofs[0];

    try std.testing.expect(!try verifyKzgProofBlobBatch(
        allocator,
        proofs,
        commitments,
        blobs.items,
        cfg,
    ));
}

test "verifyKzgProofBlobBatch: proof not in g1" {
    const allocator = std.testing.allocator;
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

    // Randomly overwrite a proof
    _ = try std.fmt.hexToBytes(&proofs[1], "8123456789abcdef0123456789abcdef0123456789abcdef8123456789abcdef0123456789abcdef0123456789abcdef");

    try std.testing.expectError(FieldError.WrongSubgroup, verifyKzgProofBlobBatch(
        allocator,
        proofs,
        commitments,
        blobs.items,
        cfg,
    ));
}

test "verifyKzgProofBlobBatch: commitment not in g1" {
    const allocator = std.testing.allocator;
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

    // Randomly overwrite a commitment
    _ = try std.fmt.hexToBytes(&commitments[1], "8123456789abcdef0123456789abcdef0123456789abcdef8123456789abcdef0123456789abcdef0123456789abcdef");

    try std.testing.expectError(FieldError.WrongSubgroup, verifyKzgProofBlobBatch(
        allocator,
        proofs,
        commitments,
        blobs.items,
        cfg,
    ));
}

test "verifyKzgProofBlobBatch: invalid blob" {
    const allocator = std.testing.allocator;
    const cfg = try KZGTrustedSetupConfig.loadFromFile(allocator, "./src/trusted_setup.txt");
    defer cfg.deinit();

    const n_samples: usize = 16;
    var proofs = try allocator.alloc([48]u8, n_samples);
    defer allocator.free(proofs);
    var commitments = try allocator.alloc([48]u8, n_samples);
    defer allocator.free(commitments);
    var blobs = try ArrayList([BYTES_PER_BLOB]u8).initCapacity(allocator, n_samples);
    defer blobs.deinit();

    for (0..n_samples - 1) |i| {
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

    // Use a bad blob for the last entry
    var fr: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&fr, "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    var blob_invalid = [_]u8{0} ** BYTES_PER_BLOB;
    @memcpy(blob_invalid[0..@sizeOf(Fr)], &fr);
    try blobs.append(blob_invalid);

    try std.testing.expectError(FieldError.InvalidUncompressedG1, verifyKzgProofBlobBatch(
        allocator,
        proofs,
        commitments,
        blobs.items,
        cfg,
    ));
}

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
});

/// Supported DKIM/ARC signing algorithms.
pub const Algorithm = enum {
    rsa_sha256,
    ed25519_sha256,
};

/// An opaque handle to a loaded signing key.
pub const SigningKey = struct {
    algorithm: Algorithm,
    rsa_pkey: ?*c.EVP_PKEY = null,
    ed25519_seed: ?[32]u8 = null,

    pub fn deinit(self: *SigningKey) void {
        if (self.rsa_pkey) |pkey| {
            c.EVP_PKEY_free(pkey);
            self.rsa_pkey = null;
        }
    }
};

/// Load a PEM-encoded RSA private key from a file path.
pub fn loadRsaKeyFile(path: []const u8) !SigningKey {
    var path_buf: [4096]u8 = undefined;
    if (path.len >= path_buf.len) return error.PathTooLong;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const bio = c.BIO_new_file(&path_buf, "r") orelse return error.FileOpenFailed;
    defer _ = c.BIO_free(bio);

    const pkey = c.PEM_read_bio_PrivateKey(bio, null, null, null) orelse return error.KeyParseFailed;

    return .{ .algorithm = .rsa_sha256, .rsa_pkey = pkey };
}

/// Load a PEM-encoded RSA private key from a byte slice.
pub fn loadRsaKeyBytes(pem_data: []const u8) !SigningKey {
    const bio = c.BIO_new_mem_buf(pem_data.ptr, @intCast(pem_data.len)) orelse return error.BioCreateFailed;
    defer _ = c.BIO_free(bio);

    const pkey = c.PEM_read_bio_PrivateKey(bio, null, null, null) orelse return error.KeyParseFailed;

    return .{ .algorithm = .rsa_sha256, .rsa_pkey = pkey };
}

/// Load a raw 32-byte Ed25519 private seed.
pub fn loadEd25519Seed(seed: [32]u8) SigningKey {
    return .{ .algorithm = .ed25519_sha256, .ed25519_seed = seed };
}

/// Sign data with an RSA-SHA256 key.
///
/// Returns the raw signature bytes. Caller owns the returned slice.
pub fn rsaSign(allocator: Allocator, pkey: *c.EVP_PKEY, data: []const u8) ![]u8 {
    const ctx = c.EVP_MD_CTX_new() orelse return error.CtxCreateFailed;
    defer c.EVP_MD_CTX_free(ctx);

    if (c.EVP_DigestSignInit(ctx, null, c.EVP_sha256(), null, pkey) != 1) {
        return error.SignInitFailed;
    }

    if (c.EVP_DigestSignUpdate(ctx, data.ptr, data.len) != 1) {
        return error.SignUpdateFailed;
    }

    var sig_len: usize = 0;
    if (c.EVP_DigestSignFinal(ctx, null, &sig_len) != 1) {
        return error.SignFinalFailed;
    }

    const sig = try allocator.alloc(u8, sig_len);
    errdefer allocator.free(sig);

    if (c.EVP_DigestSignFinal(ctx, sig.ptr, &sig_len) != 1) {
        return error.SignFinalFailed;
    }

    return allocator.realloc(sig, sig_len) catch sig[0..sig_len];
}

/// Verify an RSA-SHA256 signature.
pub fn rsaVerify(pkey: *c.EVP_PKEY, data: []const u8, signature: []const u8) !bool {
    const ctx = c.EVP_MD_CTX_new() orelse return error.CtxCreateFailed;
    defer c.EVP_MD_CTX_free(ctx);

    if (c.EVP_DigestVerifyInit(ctx, null, c.EVP_sha256(), null, pkey) != 1) {
        return error.VerifyInitFailed;
    }

    if (c.EVP_DigestVerifyUpdate(ctx, data.ptr, data.len) != 1) {
        return error.VerifyUpdateFailed;
    }

    const result = c.EVP_DigestVerifyFinal(ctx, signature.ptr, signature.len);
    return result == 1;
}

/// Load a DER-encoded RSA public key (from DNS TXT record p= tag).
pub fn loadRsaPublicKeyDer(der_data: []const u8) !*c.EVP_PKEY {
    var ptr: [*c]const u8 = der_data.ptr;
    const pkey = c.d2i_PUBKEY(null, &ptr, @intCast(der_data.len)) orelse return error.PublicKeyParseFailed;
    return pkey;
}

/// Free an EVP_PKEY returned by loadRsaPublicKeyDer.
pub fn freePublicKey(pkey: *c.EVP_PKEY) void {
    c.EVP_PKEY_free(pkey);
}

/// Ed25519 signing using Zig's std.crypto.
pub fn ed25519Sign(seed: [32]u8, data: []const u8) ![64]u8 {
    const Ed25519 = std.crypto.sign.Ed25519;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);
    const sig = try key_pair.sign(data, null);
    return sig.toBytes();
}

/// Ed25519 verification using Zig's std.crypto.
pub fn ed25519Verify(public_key: [32]u8, data: []const u8, signature: [64]u8) !bool {
    const Ed25519 = std.crypto.sign.Ed25519;
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = Ed25519.Signature.fromBytes(signature);
    sig.verify(data, pk) catch return false;
    return true;
}

/// SHA-256 hash.
pub fn sha256(data: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}

/// Incremental SHA-256 hasher for streaming body hash.
pub const Sha256Hasher = struct {
    inner: std.crypto.hash.sha2.Sha256,

    pub fn init() Sha256Hasher {
        return .{ .inner = std.crypto.hash.sha2.Sha256.init(.{}) };
    }

    pub fn update(self: *Sha256Hasher, data: []const u8) void {
        self.inner.update(data);
    }

    pub fn final(self: *Sha256Hasher) [32]u8 {
        return self.inner.finalResult();
    }
};

/// Base64 encode.
pub fn base64Encode(allocator: Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard;
    const len = encoder.Encoder.calcSize(data.len);
    const buf = try allocator.alloc(u8, len);
    const result = encoder.Encoder.encode(buf, data);
    _ = result;
    return buf;
}

/// Base64 decode.
pub fn base64Decode(allocator: Allocator, encoded: []const u8) ![]u8 {
    const decoder = std.base64.standard;
    const max_len = try decoder.Decoder.calcSizeUpperBound(encoded.len);
    const buf = try allocator.alloc(u8, max_len);
    const written = decoder.Decoder.calcSizeForSlice(encoded) catch |err| {
        allocator.free(buf);
        return @as(anyerror, err);
    };
    decoder.Decoder.decode(buf, encoded) catch |err| {
        allocator.free(buf);
        return @as(anyerror, err);
    };
    return allocator.realloc(buf, written) catch @constCast(buf[0..written]);
}

test "sha256 basic" {
    const hash = sha256("hello");
    const expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const hex = std.fmt.bytesToHex(&hash, .lower);
    try std.testing.expectEqualStrings(expected, &hex);
}

test "sha256 incremental matches one-shot" {
    const data = "The quick brown fox jumps over the lazy dog";
    const one_shot = sha256(data);

    var hasher = Sha256Hasher.init();
    hasher.update("The quick brown ");
    hasher.update("fox jumps over ");
    hasher.update("the lazy dog");
    const incremental = hasher.final();

    try std.testing.expectEqualSlices(u8, &one_shot, &incremental);
}

test "base64 round trip" {
    const original = "Hello, DKIM world!";
    const encoded = try base64Encode(std.testing.allocator, original);
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqualStrings("SGVsbG8sIERLSU0gd29ybGQh", encoded);

    const decoded = try base64Decode(std.testing.allocator, encoded);
    defer std.testing.allocator.free(decoded);

    try std.testing.expectEqualStrings(original, decoded);
}

test "ed25519 sign and verify" {
    const seed = [_]u8{0x42} ** 32;
    const data = "test message for signing";
    const sig = try ed25519Sign(seed, data);

    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pub_key = kp.public_key.toBytes();

    try std.testing.expect(try ed25519Verify(pub_key, data, sig));
    try std.testing.expect(!try ed25519Verify(pub_key, "wrong message", sig));
}

test "rsa key load from pem bytes" {
    // Minimal test: generate a key in memory via OpenSSL, sign, verify
    const ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse return error.CtxFailed;
    defer c.EVP_PKEY_CTX_free(ctx);

    if (c.EVP_PKEY_keygen_init(ctx) != 1) return error.KeygenInitFailed;
    if (c.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) != 1) return error.KeygenBitsFailed;

    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_keygen(ctx, &pkey) != 1) return error.KeygenFailed;
    defer c.EVP_PKEY_free(pkey);

    const data = "DKIM test data to sign";
    const sig = try rsaSign(std.testing.allocator, pkey.?, data);
    defer std.testing.allocator.free(sig);

    try std.testing.expect(sig.len > 0);
    try std.testing.expect(try rsaVerify(pkey.?, data, sig));
    try std.testing.expect(!try rsaVerify(pkey.?, "tampered data", sig));
}

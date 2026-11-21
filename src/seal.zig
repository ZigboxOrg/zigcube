//! Sealed store records (C5, docs/briefs/c5.md "Sealing and the key's lifecycle"). Core: no
//! files, no randomness, no clock; the shell (`server_seal.zig`) holds the key and draws nonces.
//!
//! A sealed value is one printable envelope, `zcseal1.<key id>.<base64url(nonce, ciphertext,
//! tag)>`: XChaCha20-Poly1305 with a random 24-byte nonce, the associated data being the
//! envelope's header and the store key path. So a record cannot be moved to another path, nor
//! relabelled with another key id, without failing to open. A record can still be replaced by an
//! older sealed version of the same path; only a store writer can do that, and store writers are
//! trusted (accepted, not defended).
//!
//! The key id is the first 8 bytes of SHA-256 over a domain tag and the key, in hex: enough to
//! tell which key a record expects (ZC-E0824 names it) and nothing about the key itself.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const Sha256 = std.crypto.hash.sha2.Sha256;
const base64 = std.base64.url_safe_no_pad;

pub const key_bytes = Aead.key_length;
pub const nonce_bytes = Aead.nonce_length;
pub const tag_bytes = Aead.tag_length;
pub const key_id_bytes: u32 = 16;

/// The envelope's first bytes; a new format gets a new number and this one stays readable.
pub const magic = "zcseal1.";
pub const header_bytes: u32 = magic.len + key_id_bytes + 1;

/// The prefixes whose records hold an envelope (docs/keys.md): what the start-up check opens.
pub const sealed_prefixes = [_][]const u8{ "/edge-certs/", "/acme-account/" };

/// What `--discard-sealed` deletes: the sealed records, and the orders that were made for them
/// with an account that goes too.
pub const discarded_prefixes = sealed_prefixes ++ [_][]const u8{"/acme-orders/"};

/// The envelope for a plaintext of `plain_bytes`.
pub fn envelope_bytes(plain_bytes: u32) u32 {
    assert(plain_bytes <= constants.seal_plaintext_bytes_max);
    const raw = nonce_bytes + plain_bytes + tag_bytes;
    const encoded: u32 = @intCast(base64.Encoder.calcSize(raw));
    return header_bytes + encoded;
}

pub const envelope_bytes_max = envelope_bytes_comptime(constants.seal_plaintext_bytes_max);

fn envelope_bytes_comptime(comptime plain_bytes: u32) u32 {
    const encoded = std.base64.url_safe_no_pad.Encoder.calcSize(
        nonce_bytes + plain_bytes + tag_bytes,
    );
    return header_bytes + @as(u32, @intCast(encoded));
}

comptime {
    assert(envelope_bytes_max > header_bytes);
    assert(envelope_bytes_max <= constants.store_value_bytes_max);
}

pub const KeyId = [key_id_bytes]u8;

pub const Key = struct {
    bytes: [key_bytes]u8,

    /// The key's id: printable, the same for the same key, and no help in guessing it.
    pub fn id(key: *const Key) KeyId {
        var digest: [Sha256.digest_length]u8 = undefined;
        var hash = Sha256.init(.{});
        hash.update("zcube seal key id\x00");
        hash.update(&key.bytes);
        hash.final(&digest);
        var out: KeyId = undefined;
        const hex = std.fmt.bytesToHex(digest[0..@divExact(key_id_bytes, 2)].*, .lower);
        @memcpy(&out, &hex);
        assert(is_key_id(&out));
        return out;
    }

    pub fn wipe(key: *Key) void {
        std.crypto.secureZero(u8, &key.bytes);
    }
};

pub const OpenError = error{
    /// Not an envelope of this format: no magic, a bad key id, bad base64 or too short.
    Malformed,
    /// Sealed with another key (the ids differ).
    WrongKey,
    /// The ids agree but the tag does not: the record was altered, moved to this path, or
    /// sealed with another key whose id collides.
    Forged,
};

/// Seals `plaintext` for the record at `path` into `out` (at least `envelope_bytes` long) and
/// returns the envelope. `nonce` must be fresh from a secure random source.
pub fn seal(
    key: *const Key,
    path: []const u8,
    plaintext: []const u8,
    nonce: [nonce_bytes]u8,
    out: []u8,
) []const u8 {
    assert(path.len > 0);
    assert(path[0] == '/');
    assert(plaintext.len <= constants.seal_plaintext_bytes_max);
    const length = envelope_bytes(@intCast(plaintext.len));
    assert(out.len >= length);
    const key_id = key.id();
    @memcpy(out[0..magic.len], magic);
    @memcpy(out[magic.len..][0..key_id_bytes], &key_id);
    out[header_bytes - 1] = '.';

    var raw: [nonce_bytes + constants.seal_plaintext_bytes_max + tag_bytes]u8 = undefined;
    const sealed = raw[0 .. nonce_bytes + plaintext.len + tag_bytes];
    @memcpy(sealed[0..nonce_bytes], &nonce);
    const ciphertext = sealed[nonce_bytes..][0..plaintext.len];
    const tag = sealed[nonce_bytes + plaintext.len ..][0..tag_bytes];
    var ad: AssociatedData = .{};
    Aead.encrypt(ciphertext, tag, plaintext, ad.of(out[0..header_bytes], path), nonce, key.bytes);
    const encoded = base64.Encoder.encode(out[header_bytes..length], sealed);
    assert(encoded.len == length - header_bytes);
    assert(key_id_of(out[0..length]) != null);
    return out[0..length];
}

/// Opens `envelope`, read from the record at `path`, into `out` and returns the plaintext. The
/// caller wipes `out` when done with it.
pub fn open(
    key: *const Key,
    path: []const u8,
    envelope: []const u8,
    out: []u8,
) OpenError![]u8 {
    assert(path.len > 0);
    assert(out.len >= constants.seal_plaintext_bytes_max);
    const expected = key_id_of(envelope) orelse return error.Malformed;
    const own = key.id();
    if (!std.mem.eql(u8, &expected, &own)) return error.WrongKey;
    const body = envelope[header_bytes..];
    const raw_bytes = base64.Decoder.calcSizeForSlice(body) catch return error.Malformed;
    if (raw_bytes < nonce_bytes + tag_bytes) return error.Malformed;
    if (raw_bytes > nonce_bytes + constants.seal_plaintext_bytes_max + tag_bytes) {
        return error.Malformed;
    }
    var raw: [nonce_bytes + constants.seal_plaintext_bytes_max + tag_bytes]u8 = undefined;
    base64.Decoder.decode(raw[0..raw_bytes], body) catch return error.Malformed;
    const plain_bytes = raw_bytes - nonce_bytes - tag_bytes;
    const nonce = raw[0..nonce_bytes].*;
    const ciphertext = raw[nonce_bytes..][0..plain_bytes];
    const tag = raw[nonce_bytes + plain_bytes ..][0..tag_bytes].*;
    var ad: AssociatedData = .{};
    const plaintext = out[0..plain_bytes];
    const associated = ad.of(envelope[0..header_bytes], path);
    Aead.decrypt(plaintext, ciphertext, tag, associated, nonce, key.bytes) catch {
        std.crypto.secureZero(u8, plaintext);
        return error.Forged;
    };
    assert(plaintext.len == plain_bytes);
    return plaintext;
}

/// The key id an envelope names, or null if `envelope` is not exactly one envelope.
pub fn key_id_of(envelope: []const u8) ?KeyId {
    if (envelope.len <= header_bytes) return null;
    if (!std.mem.startsWith(u8, envelope, magic)) return null;
    if (envelope[header_bytes - 1] != '.') return null;
    const id = envelope[magic.len..][0..key_id_bytes];
    if (!is_key_id(id)) return null;
    for (envelope[header_bytes..]) |byte| {
        if (!is_base64url(byte)) return null;
    }
    return id.*;
}

/// The member of a sealed record's JSON object that holds its envelope (docs/keys.md): the
/// P-256 key of an `/edge-certs/` or `/acme-account/` record. Every other member is clear.
pub const sealed_member = "key";

/// What a sealed prefix's record holds, read by its schema (`sealed_of`).
pub const Sealed = union(enum) {
    /// No sealed member: nothing sealed yet (an entry not yet given a key).
    none,
    /// The sealed member's whole text, for `open`, which refuses anything but one envelope.
    envelope: []const u8,
    /// Not a record this build can read, and why: refused, never skipped.
    unreadable: []const u8,
};

/// The sealed member of a record's value. Found by the record's schema, not by the shape of
/// its text: only the top-level member named `sealed_member` is sealed, and its whole string is
/// the envelope. So a clear member, whatever it holds (a host named
/// `zcseal1.0123456789abcdef.example.com`, a URL, an envelope copied in), is never opened and
/// never refuses the start; and a sealed member that is anything but one envelope (another
/// version's, a damaged header, a clear key) is handed to `open`, which refuses it. A value that
/// is not one JSON object, nests deeper than `seal_record_depth_max`, or names the sealed member
/// twice is unreadable (docs/decisions/2026-11-21-c5-seal-find-by-schema.md).
pub fn sealed_of(value: []const u8) Sealed {
    assert(value.len <= std.math.maxInt(u32));
    // The scanner's nesting stack, one bit a level, in a fixed buffer: a deeper value runs out
    // of it (OutOfMemory) rather than growing.
    var stack_buffer: [stack_bytes]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&stack_buffer);
    var scanner: std.json.Scanner = .initCompleteInput(fixed.allocator(), value);
    scanner.stack.bytes.ensureTotalCapacityPrecise(stack_bytes) catch
        unreachable; // The buffer is exactly `stack_bytes` and nothing else was allocated.
    assert(fixed.end_index == stack_bytes);
    const result = sealed_scan(&scanner) catch |err| return .{
        .unreadable = switch (err) {
            error.OutOfMemory => "it nests deeper than a sealed record may",
            error.SyntaxError, error.UnexpectedEndOfInput => "it is not one JSON object",
            error.BufferUnderrun => unreachable, // The input is complete.
        },
    };
    if (result == .envelope) assert(result.envelope.len <= value.len);
    return result;
}

const stack_bytes = @divExact(constants.seal_record_depth_max, 8);

fn sealed_scan(scanner: *std.json.Scanner) std.json.Scanner.NextError!Sealed {
    if (try scanner.next() != .object_begin) return .{ .unreadable = "it is not a JSON object" };
    var found: ?[]const u8 = null;
    var name_buffer: [sealed_member.len + 1]u8 = undefined;
    while (try member_name(scanner, &name_buffer)) |name| {
        if (!std.mem.eql(u8, name, sealed_member)) {
            try scanner.skipValue();
            continue;
        }
        if (found != null) return .{ .unreadable = "it names its sealed member twice" };
        // An envelope has no escapes, so it is always one whole `.string` token of the input.
        switch (try scanner.next()) {
            .string => |text| found = text,
            else => return .{ .unreadable = "its sealed member is not one envelope" },
        }
    }
    assert(scanner.stackHeight() == 0);
    if (try scanner.next() != .end_of_document) {
        return .{ .unreadable = "it is not one JSON object" };
    }
    const envelope = found orelse return .none;
    return .{ .envelope = envelope };
}

/// The next member's name of the top-level object, cut to `buffer.len` bytes (enough to tell
/// it from `sealed_member`), escapes decoded; null at the object's end.
fn member_name(
    scanner: *std.json.Scanner,
    buffer: *[sealed_member.len + 1]u8,
) std.json.Scanner.NextError!?[]const u8 {
    assert(scanner.stackHeight() == 1);
    var length: usize = 0;
    while (true) {
        const token = try scanner.next();
        const piece: []const u8 = switch (token) {
            .object_end => return null,
            .string, .partial_string => |text| text,
            .partial_string_escaped_1 => |*bytes| bytes,
            .partial_string_escaped_2 => |*bytes| bytes,
            .partial_string_escaped_3 => |*bytes| bytes,
            .partial_string_escaped_4 => |*bytes| bytes,
            else => unreachable, // The scanner gives a name or the end after `{` or a value.
        };
        const taken = @min(piece.len, buffer.len - length);
        @memcpy(buffer[length..][0..taken], piece[0..taken]);
        length += taken;
        if (token == .string) {
            assert(length <= buffer.len);
            return buffer[0..length];
        }
    }
}

pub fn is_key_id(text: []const u8) bool {
    if (text.len != key_id_bytes) return false;
    for (text) |byte| {
        const digit = byte >= '0' and byte <= '9';
        const letter = byte >= 'a' and byte <= 'f';
        if (!digit and !letter) return false;
    }
    return true;
}

fn is_base64url(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_';
}

/// The associated data: the envelope's header, a zero byte, then the store key path.
const AssociatedData = struct {
    bytes: [header_bytes + 1 + constants.store_key_bytes_max]u8 = undefined,

    fn of(ad: *AssociatedData, header: []const u8, path: []const u8) []const u8 {
        assert(header.len == header_bytes);
        assert(path.len <= constants.store_key_bytes_max);
        @memcpy(ad.bytes[0..header_bytes], header);
        ad.bytes[header_bytes] = 0;
        @memcpy(ad.bytes[header_bytes + 1 ..][0..path.len], path);
        return ad.bytes[0 .. header_bytes + 1 + path.len];
    }
};

// ---- Tests --------------------------------------------------------------------------------------

const testing = std.testing;

fn test_key(byte: u8) Key {
    return .{ .bytes = @splat(byte) };
}

test "a sealed record opens at its own path with its own key, and round-trips every length" {
    // Goal: the round trip of the brief's tests. Method: seal plaintexts from empty to the bound
    // at one path, check the envelope's shape and length, open each and compare.
    const key = test_key(0x11);
    var plain: [constants.seal_plaintext_bytes_max]u8 = undefined;
    for (&plain, 0..) |*byte, index| byte.* = @truncate(index *% 7 +% 3);
    var out: [envelope_bytes_max]u8 = undefined;
    var opened: [constants.seal_plaintext_bytes_max]u8 = @splat(0xee);
    const lengths = [_]u32{ 0, 1, 2, 3, 32, 121, constants.seal_plaintext_bytes_max };
    for (lengths) |length| {
        const nonce: [nonce_bytes]u8 = @splat(@truncate(length));
        const envelope = seal(&key, "/edge-certs/a.example", plain[0..length], nonce, &out);
        try testing.expectEqual(envelope_bytes(length), @as(u32, @intCast(envelope.len)));
        try testing.expectEqualSlices(u8, &key.id(), &key_id_of(envelope).?);
        var value: [envelope_bytes_max + 16]u8 = undefined;
        const record = try std.fmt.bufPrint(&value, "{{\"key\":\"{s}\"}}", .{envelope});
        try testing.expectEqualStrings(envelope, sealed_of(record).envelope);
        const back = try open(&key, "/edge-certs/a.example", envelope, &opened);
        try testing.expectEqualSlices(u8, plain[0..length], back);
    }
}

test "a moved record, a tampered byte, a relabelled key id and another key are refused" {
    // Goal: the brief's "a moved record refused" and "a tampered byte refused". Method: seal at
    // one path; open at another (Forged); flip each byte of the envelope in turn (never opens);
    // put another key's id in the header (Forged: the id is bound); open with another key.
    const key = test_key(0x22);
    const plain = "the leaf key";
    var out: [envelope_bytes_max]u8 = undefined;
    const nonce: [nonce_bytes]u8 = @splat(5);
    const envelope = seal(&key, "/edge-certs/a.example", plain, nonce, &out);
    var opened: [constants.seal_plaintext_bytes_max]u8 = undefined;
    try testing.expectError(error.Forged, open(&key, "/edge-certs/b.example", envelope, &opened));
    try testing.expectError(error.Forged, open(&key, "/acme-account/a", envelope, &opened));

    var copy: [envelope_bytes_max]u8 = undefined;
    for (0..envelope.len) |index| {
        @memcpy(copy[0..envelope.len], envelope);
        copy[index] = if (copy[index] == 'A') 'B' else 'A';
        const result = open(&key, "/edge-certs/a.example", copy[0..envelope.len], &opened);
        if (result) |_| return error.TamperedRecordOpened else |_| {}
    }

    const other = test_key(0x33);
    const path = "/edge-certs/a.example";
    try testing.expectError(error.WrongKey, open(&other, path, envelope, &opened));
    @memcpy(copy[0..envelope.len], envelope);
    @memcpy(copy[magic.len..][0..key_id_bytes], &other.id());
    const relabelled = copy[0..envelope.len];
    try testing.expectError(error.Forged, open(&other, path, relabelled, &opened));
}

test "the sealed member is found by the record's schema, and junk is unreadable" {
    // Goal: the start-up check's parser. Method: the envelope in the `key` member is found whole
    // wherever the member sits; values without the member hold nothing sealed; values that are
    // not one JSON object, nest too deep, name the member twice or give it a non-string are
    // unreadable; and `key_id_of` and `open` refuse a cut-short or damaged envelope.
    const key = test_key(0x44);
    var out: [envelope_bytes_max]u8 = undefined;
    const envelope = seal(&key, "/acme-account/0123", "account", @splat(9), &out);
    var value_buffer: [envelope_bytes_max + 64]u8 = undefined;
    var value = try std.fmt.bufPrint(&value_buffer, "{{\"x\":[1,{{}}],\"key\":\"{s}\"}}", .{
        envelope,
    });
    try testing.expectEqualStrings(envelope, sealed_of(value).envelope);
    // An escaped name is the same name.
    value = try std.fmt.bufPrint(&value_buffer, "{{\"k\\u0065y\":\"{s}\"}}", .{envelope});
    try testing.expectEqualStrings(envelope, sealed_of(value).envelope);
    try testing.expect(sealed_of("{\"state\":\"pending\",\"keys\":\"x\",\"ke\":1}") == .none);
    try testing.expect(sealed_of("{\"a\":{\"key\":\"zcseal1.0123456789abcdef.AAAA\"}}") == .none);
    try testing.expect(sealed_of("{}") == .none);

    const unreadable = [_][]const u8{
        "",                              "zcseal1.0123456789abcdef.AAAA",
        "[\"key\"]",                     "{\"key\":\"a\"} {}",
        "{\"key\":\"a\",\"key\":\"b\"}", "{\"key\":1}",
        "{\"key\":{\"v\":\"a\"}}",       "{\"key\":\"zcseal1.\\u0030\"}",
        "{\"key\":\"a\"",                "{\"key\" \"a\"}",
    };
    for (unreadable) |text| try testing.expect(sealed_of(text) == .unreadable);
    // Depth: the bound itself is read, one level more is not.
    var deep_buffer: [6 * (constants.seal_record_depth_max + 1)]u8 = undefined;
    try testing.expect(sealed_of(nested(&deep_buffer, constants.seal_record_depth_max)) == .none);
    const deeper = nested(&deep_buffer, constants.seal_record_depth_max + 1);
    const why = sealed_of(deeper).unreadable;
    try testing.expectEqualStrings("it nests deeper than a sealed record may", why);

    try testing.expect(key_id_of("zcseal1.0123456789abcdef.") == null);
    try testing.expect(key_id_of("zcseal1.0123456789ABCDEF.AAAA") == null);
    try testing.expect(key_id_of("zcseal1.0123456789abcdef-AAAA") == null);
    try testing.expect(key_id_of("zcseal1.0123456789abcdef.AA=A") == null);
    try testing.expect(key_id_of("zcseal1.0123456789abcdef.example") != null);
    try testing.expect(key_id_of("zcseal1.0123456789abcdef.AAAA") != null);
    var opened: [constants.seal_plaintext_bytes_max]u8 = undefined;
    var short_buffer: [header_bytes + 4]u8 = undefined;
    const short = try std.fmt.bufPrint(&short_buffer, "{s}{s}.AAAA", .{ magic, &key.id() });
    try testing.expectError(error.Malformed, open(&key, "/edge-certs/x", short, &opened));
}

/// `{"a":` nested `depth` objects deep, the innermost empty: `{"a":{"a":{}}}` is depth 3.
fn nested(buffer: []u8, depth: u32) []const u8 {
    assert(depth >= 1);
    assert(buffer.len >= 6 * depth);
    var length: usize = 0;
    for (0..depth - 1) |_| {
        @memcpy(buffer[length..][0..5], "{\"a\":");
        length += 5;
    }
    buffer[length] = '{';
    length += 1;
    @memset(buffer[length..][0..depth], '}');
    length += depth;
    return buffer[0..length];
}

test "a clear member shaped like an envelope is never opened and never refuses the record" {
    // Goal: review of PR #8 (MUST): a clear host such as `zcseal1.0123456789abcdef.example.com`
    // (a 16-hex DNS label is legal) was taken for an envelope and refused every start, which
    // `--discard-sealed` could not cure. Method: such clear members, one ending at the quote,
    // one an envelope from end to end, beside the sealed member yield exactly the sealed member,
    // which opens; a record with only such clear members holds nothing sealed.
    const key = test_key(0x45);
    var out: [envelope_bytes_max]u8 = undefined;
    const path = "/edge-certs/zcseal1.0123456789abcdef.example.com";
    const envelope = seal(&key, path, "leaf", @splat(3), &out);
    const other = test_key(0x46);
    var other_out: [envelope_bytes_max]u8 = undefined;
    const foreign = seal(&other, path, "copied", @splat(4), &other_out);
    var value_buffer: [2 * envelope_bytes_max + 256]u8 = undefined;
    const clear = "\"host\":\"zcseal1.0123456789abcdef.example.com\"," ++
        "\"alias\":\"zcseal1.0123456789abcdef.dev\",\"url\":\"https://zcseal7.x/zcseal1.\"";
    const value = try std.fmt.bufPrint(
        &value_buffer,
        "{{" ++ clear ++ ",\"copy\":\"{s}\",\"key\":\"{s}\"," ++
            "\"after\":\"zcseal1.0123456789abcdef.x\"}}",
        .{ foreign, envelope },
    );
    const found = sealed_of(value).envelope;
    try testing.expectEqualStrings(envelope, found);
    var opened: [constants.seal_plaintext_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("leaf", try open(&key, path, found, &opened));
    try testing.expect(sealed_of("{" ++ clear ++ "}") == .none);
}

test "a sealed member of another version, or damaged, is refused by open, never skipped" {
    // Goal: a `zcseal2.` met after a downgrade, and a damaged header, refuse the record. Method:
    // the sealed member holding a version-2 header, an upper-case key id, or a clear value is
    // returned whole, and `open` refuses each as `Malformed`.
    const a = test_key(0x46);
    const path = "/acme-account/0123";
    var out: [envelope_bytes_max]u8 = undefined;
    const first = seal(&a, path, "one", @splat(1), &out);
    var opened: [constants.seal_plaintext_bytes_max]u8 = undefined;
    var later_buffer: [envelope_bytes_max + 64]u8 = undefined;
    var later = try std.fmt.bufPrint(&later_buffer, "{{\"key\":\"zcseal2.{s}\"}}", .{
        first["zcseal1.".len..],
    });
    const unknown = sealed_of(later).envelope;
    try testing.expect(std.mem.startsWith(u8, unknown, "zcseal2."));
    try testing.expectError(error.Malformed, open(&a, path, unknown, &opened));
    later = try std.fmt.bufPrint(&later_buffer, "{{\"key\":\"{s}\"}}", .{first});
    const at = std.mem.indexOf(u8, later, "zcseal1.").? + magic.len;
    later[at] = std.ascii.toUpper(later[at]);
    later[at + 1] = 'G';
    try testing.expectError(error.Malformed, open(&a, path, sealed_of(later).envelope, &opened));
    const clear = sealed_of("{\"key\":\"-----BEGIN EC PRIVATE KEY-----\"}").envelope;
    try testing.expectError(error.Malformed, open(&a, path, clear, &opened));
}

test "known answer: the envelope's bytes and the key id are pinned" {
    // Goal: review of #284: the on-disk format cannot change unnoticed (the AD order, the key-id
    // label and truncation, nonce || ciphertext || tag, the base64 alphabet). Method: a fixed
    // key, nonce, path and plaintext give exactly this envelope, and it opens to the plaintext.
    var key: Key = .{ .bytes = undefined };
    for (&key.bytes, 0..) |*byte, index| byte.* = @intCast(index);
    var nonce: [nonce_bytes]u8 = undefined;
    for (&nonce, 0..) |*byte, index| byte.* = @intCast(0xa0 + index);
    const path = "/edge-certs/a.example";
    const plain = "the leaf key";
    try testing.expectEqualStrings("10d49fcffe05434d", &key.id());
    var out: [envelope_bytes_max]u8 = undefined;
    const envelope = seal(&key, path, plain, nonce, &out);
    try testing.expectEqualStrings("zcseal1.10d49fcffe05434d." ++
        "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3MYRvPds4xcpBBEjwa5brdFDtbyBgT8hcev1Yog", envelope);
    var opened: [constants.seal_plaintext_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(plain, try open(&key, path, envelope, &opened));
}

test "known answer: draft-irtf-cfrg-xchacha-03, A.3.1, through Aead" {
    // Goal: the primitive is pinned as well as the framing. Method: the draft's AEAD test vector.
    const plain = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip " ++
        "for the future, sunscreen would be it.";
    const ad = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    var key: [key_bytes]u8 = undefined;
    for (&key, 0..) |*byte, index| byte.* = @intCast(0x80 + index);
    var nonce: [nonce_bytes]u8 = undefined;
    for (&nonce, 0..) |*byte, index| byte.* = @intCast(0x40 + index);
    const expected_hex = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" ++
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" ++
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" ++
        "21f9664c97637da9768812f615c68b13b52e";
    const tag_hex = "c0875924c1c7987947deafd8780acf49";
    var ciphertext: [plain.len]u8 = undefined;
    var tag: [tag_bytes]u8 = undefined;
    Aead.encrypt(&ciphertext, &tag, plain, &ad, nonce, key);
    var expected: [plain.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    var expected_tag: [tag_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_tag, tag_hex);
    try testing.expectEqualSlices(u8, &expected, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
}

test "key ids differ between keys and do not contain the key" {
    // Goal: E0824 may print an id without exposing the key. Method: two keys, two ids; the id is
    // not the key's leading hex.
    const a = test_key(0x01);
    const b = test_key(0x02);
    try testing.expect(!std.mem.eql(u8, &a.id(), &b.id()));
    const hex = std.fmt.bytesToHex(a.bytes, .lower);
    try testing.expect(std.mem.indexOf(u8, &hex, &a.id()) == null);
}

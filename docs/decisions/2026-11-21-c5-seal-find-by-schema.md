# Sealed members are found by the record's schema, not by the shape of their text

*Decided 2026-11-21, by the fix session for PR #8's review (C5 slice 2), on the review's MUST. It
replaces ruling 3 ("Finding envelopes") of `2026-11-18-c5-seal-fix-discard-and-find.md`; the
rest of that file stands.*

## Why

Ruling 3 found envelopes by their text: anything in a value of the shape `zcseal<digits>.<16
hex>.` was opened. A 16-hex DNS label is legal, so a clear member such as a host named
`zcseal1.0123456789abcdef.example.com` was taken for an envelope: it does not open (WrongKey),
and `zcseal1.0123456789abcdef.dev"` is Malformed. Either refused every start with ZC-E0824, and
`--discard-sealed` could not help: the next record written with that host refused the start
again. The shape of a clear value is not ours to choose, so no shape rule can be safe.

## The rule

- **One sealed member, by name.** A sealed record (`/edge-certs/`, `/acme-account/`) is one JSON
  object, and its secret is the top-level member `key` (`seal.sealed_member`), a string holding
  exactly one envelope. Every other member is clear, whatever its text, and is never opened.
  `seal.sealed_of(value)` returns `.none`, `.envelope` or `.unreadable` with a reason.
- **No `key` member, or `"key":null`,** is `.none`: an entry not yet given a key holds nothing
  sealed, as before. `null` is what `std.json.Stringify` writes for a null optional field (its
  `emit_null_optional_fields` defaults to true), so a writer whose type has `key: ?[]const u8 =
  null` and keeps std's defaults must not refuse every start. `null` still names the member: a
  second `key` after it is refused as named twice.
- **`"key":""` is refused** ("its sealed member is empty"), not read as nothing sealed. No
  envelope is empty (sealing no bytes still gives a header, a nonce and a tag), and std writes a
  pending optional as `null`, never `""`; an empty string is a key that was wiped or cut short,
  and taking it for an entry not yet given a key would hide that. A writer marks a pending entry
  by leaving `key` out or writing `null`, never `""`.
- **Refused, never skipped.** A `key` member that is anything but one envelope (another version's
  header, a damaged key id, a clear PEM, two envelopes run together) is handed to `open`, which
  refuses it (Malformed or WrongKey): ZC-E0824. Ruling 3's accepted gap (a damaged key id was
  skipped) is closed.
- **Unreadable is refused.** A value that is not one JSON object (trailing text included), names
  `key` twice, holds a `key` that is not a string, or nests deeper than `seal_record_depth_max`
  (64) is refused with ZC-E0824 and its reason ("it is not one JSON object", "it names its sealed
  member twice", "its sealed member is not one envelope", "it nests deeper than a sealed record
  may", "its sealed member is empty"). A name is matched after JSON unescaping (`k\u0065y` is
  `key`).
- **A damaged record is named, and deleting it is the fix.** A record no key can open (any
  unreadable value above, or a `key` that `open` finds Malformed: no envelope header of this
  version, a body of the wrong length or alphabet) is the record's fault, not the key file's. Its
  ZC-E0824 drops the key-id cause, says "<record> cannot be read under any key: <why>", and its
  first fix is to delete that record from the store and start again; `--discard-sealed` is the
  fallback. A record sealed with another key, or that does not authenticate, keeps the key-id
  message and the restore fix. Still no new code: the summary ("sealed records do not open with
  this server's sealing key") holds for both, and the explanation says which is which.
- **Writers use the name.** A record type written under a sealed prefix names its sealed field
  `seal.sealed_member` and is checked at comptime with `seal.sealed_record(T)`, which fails the
  build for a type without a top-level string (or optional string) field of that name; a writer
  that called it `account_key`, or nested it, would leave every record unchecked at start.
- **The depth bound is internal.** `seal_record_depth_max` sizes the JSON scanner's nesting stack
  in a fixed buffer (8 bytes), so the check allocates nothing per record. No writer exists yet
  (slice 3b writes the first records), and the records planned nest a few levels, far inside
  the bound. It is not a limit an operator meets, and changes no default. **No new
  code**: every refusal is the existing ZC-E0824.

Where: `src/seal.zig` (`sealed_member`, `sealed_record`, `Sealed`, `sealed_of`),
`src/server_seal.zig` (`check_one`, `raise_damaged`), `src/diag/codes.zig` (E0824's
explanation), `src/constants.zig` (`seal_record_depth_max`), `docs/sealing.md` ("At start", "Writers"),
`docs/keys.md`.

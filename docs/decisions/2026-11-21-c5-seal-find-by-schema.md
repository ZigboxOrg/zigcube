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
- **No `key` member** is `.none`: an entry not yet given a key holds nothing sealed, as before.
- **Refused, never skipped.** A `key` member that is anything but one envelope (another version's
  header, a damaged key id, a clear PEM, two envelopes run together) is handed to `open`, which
  refuses it (Malformed or WrongKey): ZC-E0824. Ruling 3's accepted gap (a damaged key id was
  skipped) is closed.
- **Unreadable is refused.** A value that is not one JSON object (trailing text included), names
  `key` twice, holds a `key` that is not a string, or nests deeper than `seal_record_depth_max`
  (64) is refused with ZC-E0824 and its reason ("it is not one JSON object", "it names its sealed
  member twice", "its sealed member is not one envelope", "it nests deeper than a sealed record
  may"). A name is matched after JSON unescaping (`key` is `key`).
- **The depth bound is internal.** `seal_record_depth_max` sizes the JSON scanner's nesting stack
  in a fixed buffer (8 bytes), so the check allocates nothing per record; every record the server
  writes nests two levels. It is not a limit an operator meets, and changes no default. **No new
  code**: every refusal is the existing ZC-E0824.

Where: `src/seal.zig` (`sealed_member`, `Sealed`, `sealed_of`), `src/server_seal.zig`
(`check_one`), `src/constants.zig` (`seal_record_depth_max`), `docs/sealing.md` ("At start"),
`docs/keys.md`.

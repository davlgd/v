// Package cbor implements RFC 8949 (Concise Binary Object Representation).
//
// Three layers of API are available:
//
//   * `encode[T]` / `decode[T]` — comptime-driven generic API. Works on
//     primitives, strings, arrays, maps, structs (with `@[cbor: 'name']`
//     and `@[skip]` attributes), enums, `time.Time` (auto-tagged), and
//     any type implementing `Marshaler` / `Unmarshaler`.
//
//   * `Packer` / `Unpacker` — manual streaming API. Use when the schema
//     isn't known at compile time, or when you need full control over
//     tags, indefinite-length items and simple values.
//
//   * `Value` sumtype — dynamic representation for round-tripping
//     unknown payloads or inspecting tagged data.
//
// Defaults follow RFC 8949 *preferred serialisation* (§4.2.2): floats
// shrink to the shortest IEEE 754 width that preserves their value, and
// every length argument uses the shortest encoding. Set
// `EncodeOpts.canonical = true` to additionally sort map keys for
// hash/signature stability (§4.2.1, deterministic encoding).
module cbor

// encode serialises any V value into CBOR bytes. The returned slice
// owns its backing buffer (V's GC tracks it) — no copy, so the returned
// bytes are safe to keep across calls and to pass to other modules.
pub fn encode[T](val T, opts EncodeOpts) ![]u8 {
	mut p := new_packer(opts)
	p.pack[T](val)!
	return p.bytes()
}

// decode parses CBOR bytes into a value of type T.
pub fn decode[T](data []u8, opts DecodeOpts) !T {
	mut u := new_unpacker(data, opts)
	return u.unpack[T]()!
}

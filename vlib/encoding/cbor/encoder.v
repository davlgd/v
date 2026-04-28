module cbor

import math

// EncodeOpts tunes the encoder. Defaults yield RFC 8949 *preferred*
// serialisation: floats shrink to the shortest IEEE 754 width that
// preserves their value, headers use the shortest length encoding.
//
// Setting `canonical = true` additionally sorts map keys per RFC 8949
// §4.2.1 (deterministic encoding) — useful for hashing/signing.
pub struct EncodeOpts {
pub:
	initial_cap   int = 64
	canonical     bool // sort map keys, definite-length only
	self_describe bool // prepend tag 55799 (`d9 d9 f7`)
}

// Packer accumulates CBOR bytes into an internal buffer. Use `bytes()`
// to retrieve the wire output, or `reset()` to reuse the buffer for the
// next message — that's the cheapest way to emit many small frames.
pub struct Packer {
pub mut:
	buf  []u8
	opts EncodeOpts
}

// new_packer builds a Packer with the given options. `opts.initial_cap`
// reserves the buffer up-front; oversize is harmless, undersize triggers
// the usual growth policy.
pub fn new_packer(opts EncodeOpts) Packer {
	cap := if opts.initial_cap > 0 { opts.initial_cap } else { 64 }
	mut p := Packer{
		buf:  []u8{cap: cap}
		opts: opts
	}
	if opts.self_describe {
		p.buf << self_describe_prefix
	}
	return p
}

// bytes returns the encoded buffer. The returned slice aliases the
// Packer's storage — clone it if you keep using the Packer.
@[inline]
pub fn (mut p Packer) bytes() []u8 {
	return p.buf
}

// reset clears the buffer for reuse. The capacity is preserved, so this
// is the fast path for high-throughput senders.
@[inline]
pub fn (mut p Packer) reset() {
	unsafe {
		p.buf.len = 0
	}
	if p.opts.self_describe {
		p.buf << self_describe_prefix
	}
}

// reserve grows the buffer's capacity by at least `n` bytes. Useful
// before a string/binary write of known length to skip per-byte growth.
@[inline]
pub fn (mut p Packer) reserve(n int) {
	if n <= 0 {
		return
	}
	needed := p.buf.len + n
	if needed > p.buf.cap {
		mut new_cap := if p.buf.cap == 0 { 64 } else { p.buf.cap * 2 }
		for new_cap < needed {
			new_cap *= 2
		}
		mut grown := []u8{cap: new_cap}
		grown << p.buf
		p.buf = grown
	}
}

// extend_unchecked grows the buffer's length by `n`. The caller must
// have already ensured enough capacity via `reserve`. Returns the
// position at which the new bytes start.
@[direct_array_access; inline]
fn (mut p Packer) extend_unchecked(n int) int {
	pos := p.buf.len
	unsafe {
		p.buf.len = pos + n
	}
	return pos
}

// --------------------------------------------------------------------
// Low-level head writer
// --------------------------------------------------------------------

// write_head emits an initial byte (major type | additional info) plus
// the appropriate big-endian argument. Always uses the shortest encoding
// (RFC 8949 §4.2.1, "preferred serialization"). Hot path: avoid the
// `<<` operator (which carries cap-grow checks per byte) by reserving
// once, then using direct unsafe index writes.
@[direct_array_access; inline]
fn (mut p Packer) write_head(major u8, arg u64) {
	if arg < 24 {
		p.reserve(1)
		pos := p.extend_unchecked(1)
		unsafe {
			p.buf[pos] = major | u8(arg)
		}
		return
	}
	if arg <= 0xff {
		p.reserve(2)
		pos := p.extend_unchecked(2)
		unsafe {
			p.buf[pos] = major | 24
			p.buf[pos + 1] = u8(arg)
		}
		return
	}
	if arg <= 0xffff {
		p.reserve(3)
		pos := p.extend_unchecked(3)
		unsafe {
			p.buf[pos] = major | 25
			p.buf[pos + 1] = u8(arg >> 8)
			p.buf[pos + 2] = u8(arg)
		}
		return
	}
	if arg <= 0xffffffff {
		p.reserve(5)
		pos := p.extend_unchecked(5)
		unsafe {
			p.buf[pos] = major | 26
			p.buf[pos + 1] = u8(arg >> 24)
			p.buf[pos + 2] = u8(arg >> 16)
			p.buf[pos + 3] = u8(arg >> 8)
			p.buf[pos + 4] = u8(arg)
		}
		return
	}
	p.reserve(9)
	pos := p.extend_unchecked(9)
	unsafe {
		p.buf[pos] = major | 27
		p.buf[pos + 1] = u8(arg >> 56)
		p.buf[pos + 2] = u8(arg >> 48)
		p.buf[pos + 3] = u8(arg >> 40)
		p.buf[pos + 4] = u8(arg >> 32)
		p.buf[pos + 5] = u8(arg >> 24)
		p.buf[pos + 6] = u8(arg >> 16)
		p.buf[pos + 7] = u8(arg >> 8)
		p.buf[pos + 8] = u8(arg)
	}
}

@[direct_array_access; inline]
fn (mut p Packer) write_be_u16(v u16) {
	p.reserve(2)
	pos := p.extend_unchecked(2)
	unsafe {
		p.buf[pos] = u8(v >> 8)
		p.buf[pos + 1] = u8(v)
	}
}

@[direct_array_access; inline]
fn (mut p Packer) write_be_u32(v u32) {
	p.reserve(4)
	pos := p.extend_unchecked(4)
	unsafe {
		p.buf[pos] = u8(v >> 24)
		p.buf[pos + 1] = u8(v >> 16)
		p.buf[pos + 2] = u8(v >> 8)
		p.buf[pos + 3] = u8(v)
	}
}

@[direct_array_access; inline]
fn (mut p Packer) write_be_u64(v u64) {
	p.reserve(8)
	pos := p.extend_unchecked(8)
	unsafe {
		p.buf[pos] = u8(v >> 56)
		p.buf[pos + 1] = u8(v >> 48)
		p.buf[pos + 2] = u8(v >> 40)
		p.buf[pos + 3] = u8(v >> 32)
		p.buf[pos + 4] = u8(v >> 24)
		p.buf[pos + 5] = u8(v >> 16)
		p.buf[pos + 6] = u8(v >> 8)
		p.buf[pos + 7] = u8(v)
	}
}

// --------------------------------------------------------------------
// High-level packers — primitives
// --------------------------------------------------------------------

// pack_uint emits a CBOR unsigned-integer (major type 0). Covers the
// full u64 range, including values above i64.max.
@[inline]
pub fn (mut p Packer) pack_uint(v u64) {
	p.write_head(0x00, v)
}

// pack_int picks the right major type for a signed integer.
// For values below i64.min that can still fit -1-u64, prefer
// `pack_negative_arg`.
@[inline]
pub fn (mut p Packer) pack_int(v i64) {
	if v >= 0 {
		p.write_head(0x00, u64(v))
	} else {
		p.write_head(0x20, u64(-1 - v))
	}
}

// pack_negative_arg writes a major type 1 value where the encoded
// argument is `arg` and the represented integer is `-1 - arg`. Lets you
// emit values down to -2^64 (the lower bound of CBOR negative ints).
@[inline]
pub fn (mut p Packer) pack_negative_arg(arg u64) {
	p.write_head(0x20, arg)
}

// pack_bool emits the simple value 20 (false) or 21 (true).
@[direct_array_access; inline]
pub fn (mut p Packer) pack_bool(v bool) {
	p.reserve(1)
	pos := p.extend_unchecked(1)
	unsafe {
		p.buf[pos] = if v { u8(0xf5) } else { u8(0xf4) }
	}
}

// pack_null emits CBOR null (simple value 22, byte 0xf6).
@[direct_array_access; inline]
pub fn (mut p Packer) pack_null() {
	p.reserve(1)
	pos := p.extend_unchecked(1)
	unsafe {
		p.buf[pos] = 0xf6
	}
}

// pack_undefined emits CBOR undefined (simple value 23, byte 0xf7).
@[direct_array_access; inline]
pub fn (mut p Packer) pack_undefined() {
	p.reserve(1)
	pos := p.extend_unchecked(1)
	unsafe {
		p.buf[pos] = 0xf7
	}
}

// pack_simple emits a CBOR simple value. Values 0..23 use the inline
// form, values 32..255 use the 1-byte trailer form. Values 24..31 are
// not well-formed per RFC 8949 §3.3 and are rejected here.
@[direct_array_access]
pub fn (mut p Packer) pack_simple(v u8) ! {
	if v < 24 {
		p.reserve(1)
		pos := p.extend_unchecked(1)
		unsafe {
			p.buf[pos] = 0xe0 | v
		}
		return
	}
	if v < 32 {
		return error('cbor: simple values 24..31 are not well-formed (RFC 8949 §3.3)')
	}
	p.reserve(2)
	pos := p.extend_unchecked(2)
	unsafe {
		p.buf[pos] = 0xf8
		p.buf[pos + 1] = v
	}
}

// --------------------------------------------------------------------
// High-level packers — strings and bytes
// --------------------------------------------------------------------

// pack_text writes a UTF-8 text string (major type 3). Single-shot
// reservation: the head + payload bytes are appended via one capacity
// check and one memcpy.
@[direct_array_access]
pub fn (mut p Packer) pack_text(s string) {
	if s.len < 24 {
		// Short string: head + payload fit in s.len + 1 bytes.
		total := s.len + 1
		p.reserve(total)
		pos := p.extend_unchecked(total)
		unsafe {
			p.buf[pos] = u8(0x60) | u8(s.len)
			if s.len > 0 {
				vmemcpy(&p.buf[pos + 1], s.str, s.len)
			}
		}
		return
	}
	p.write_head(0x60, u64(s.len))
	p.reserve(s.len)
	unsafe { p.buf.push_many(s.str, s.len) }
}

// pack_bytes writes a byte string (major type 2).
@[direct_array_access]
pub fn (mut p Packer) pack_bytes(b []u8) {
	if b.len < 24 {
		total := b.len + 1
		p.reserve(total)
		pos := p.extend_unchecked(total)
		unsafe {
			p.buf[pos] = u8(0x40) | u8(b.len)
			if b.len > 0 {
				vmemcpy(&p.buf[pos + 1], b.data, b.len)
			}
		}
		return
	}
	p.write_head(0x40, u64(b.len))
	p.reserve(b.len)
	unsafe { p.buf.push_many(b.data, b.len) }
}

// --------------------------------------------------------------------
// High-level packers — arrays, maps, tags
// --------------------------------------------------------------------

// pack_array_header writes the prefix for a definite-length array.
@[inline]
pub fn (mut p Packer) pack_array_header(n u64) {
	p.write_head(0x80, n)
}

// pack_map_header writes the prefix for a definite-length map. The
// argument is the number of *pairs*, not items.
@[inline]
pub fn (mut p Packer) pack_map_header(n u64) {
	p.write_head(0xa0, n)
}

// pack_tag writes a tag header (major type 6). The next packed item is
// the tag's content.
@[inline]
pub fn (mut p Packer) pack_tag(number u64) {
	p.write_head(0xc0, number)
}

// pack_array_indef opens an indefinite-length array. Close with
// `pack_break`.
@[direct_array_access; inline]
pub fn (mut p Packer) pack_array_indef() {
	p.reserve(1)
	pos := p.extend_unchecked(1)
	unsafe {
		p.buf[pos] = 0x9f
	}
}

// pack_map_indef opens an indefinite-length map. Close with `pack_break`.
@[direct_array_access; inline]
pub fn (mut p Packer) pack_map_indef() {
	p.reserve(1)
	pos := p.extend_unchecked(1)
	unsafe {
		p.buf[pos] = 0xbf
	}
}

// pack_text_indef opens an indefinite-length text string. Each chunk
// must be a definite-length text string; close with `pack_break`.
@[direct_array_access; inline]
pub fn (mut p Packer) pack_text_indef() {
	p.reserve(1)
	pos := p.extend_unchecked(1)
	unsafe {
		p.buf[pos] = 0x7f
	}
}

// pack_bytes_indef opens an indefinite-length byte string. Each chunk
// must be a definite-length byte string; close with `pack_break`.
@[direct_array_access; inline]
pub fn (mut p Packer) pack_bytes_indef() {
	p.reserve(1)
	pos := p.extend_unchecked(1)
	unsafe {
		p.buf[pos] = 0x5f
	}
}

// pack_break writes the break stop code 0xff that terminates an
// indefinite-length item.
@[direct_array_access; inline]
pub fn (mut p Packer) pack_break() {
	p.reserve(1)
	pos := p.extend_unchecked(1)
	unsafe {
		p.buf[pos] = 0xff
	}
}

// --------------------------------------------------------------------
// High-level packers — floats with preferred serialisation
// --------------------------------------------------------------------

// pack_float64 always emits an 8-byte IEEE 754 float.
@[direct_array_access; inline]
pub fn (mut p Packer) pack_float64(v f64) {
	p.reserve(9)
	pos := p.extend_unchecked(9)
	bits := math.f64_bits(v)
	unsafe {
		p.buf[pos] = 0xfb
		p.buf[pos + 1] = u8(bits >> 56)
		p.buf[pos + 2] = u8(bits >> 48)
		p.buf[pos + 3] = u8(bits >> 40)
		p.buf[pos + 4] = u8(bits >> 32)
		p.buf[pos + 5] = u8(bits >> 24)
		p.buf[pos + 6] = u8(bits >> 16)
		p.buf[pos + 7] = u8(bits >> 8)
		p.buf[pos + 8] = u8(bits)
	}
}

// pack_float32 always emits a 4-byte IEEE 754 float.
@[direct_array_access; inline]
pub fn (mut p Packer) pack_float32(v f32) {
	p.reserve(5)
	pos := p.extend_unchecked(5)
	bits := math.f32_bits(v)
	unsafe {
		p.buf[pos] = 0xfa
		p.buf[pos + 1] = u8(bits >> 24)
		p.buf[pos + 2] = u8(bits >> 16)
		p.buf[pos + 3] = u8(bits >> 8)
		p.buf[pos + 4] = u8(bits)
	}
}

// pack_float16_bits always emits a 2-byte IEEE 754 float.
@[direct_array_access; inline]
pub fn (mut p Packer) pack_float16_bits(bits u16) {
	p.reserve(3)
	pos := p.extend_unchecked(3)
	unsafe {
		p.buf[pos] = 0xf9
		p.buf[pos + 1] = u8(bits >> 8)
		p.buf[pos + 2] = u8(bits)
	}
}

// pack_float emits the shortest IEEE 754 width that preserves the value,
// per RFC 8949 §4.2.2. NaN serialises as the canonical quiet NaN
// (0xf97e00), not the original payload.
@[direct_array_access]
pub fn (mut p Packer) pack_float(v f64) {
	if math.is_nan(v) {
		p.pack_float16_bits(half_qnan_bits)
		return
	}
	if math.is_inf(v, 1) {
		p.pack_float16_bits(half_pos_inf_bits)
		return
	}
	if math.is_inf(v, -1) {
		p.pack_float16_bits(half_neg_inf_bits)
		return
	}
	// Try f32: lossless conversion?
	f32_v := f32(v)
	if f64(f32_v) == v {
		bits16, ok := f32_to_half(f32_v)
		if ok {
			p.pack_float16_bits(bits16)
			return
		}
		p.pack_float32(f32_v)
		return
	}
	p.pack_float64(v)
}

// --------------------------------------------------------------------
// Value tree encoder
// --------------------------------------------------------------------

// pack_value emits an arbitrary `Value` tree, honouring the original
// float width hint. Map keys are sorted when `opts.canonical` is set.
pub fn (mut p Packer) pack_value(v Value) {
	match v {
		IntNum {
			if v.negative {
				p.write_head(0x20, v.magnitude)
			} else {
				p.write_head(0x00, v.magnitude)
			}
		}
		Bytes {
			p.pack_bytes(v.data)
		}
		Text {
			p.pack_text(v.value)
		}
		Array {
			p.pack_array_header(u64(v.elements.len))
			for el in v.elements {
				p.pack_value(el)
			}
		}
		Map {
			p.pack_map_header(u64(v.pairs.len))
			if p.opts.canonical {
				p.pack_map_canonical(v.pairs)
			} else {
				for pair in v.pairs {
					p.pack_value(pair.key)
					p.pack_value(pair.value)
				}
			}
		}
		Tag {
			p.pack_tag(v.number)
			if v.content_box.len > 0 {
				p.pack_value(v.content_box[0])
			} else {
				p.pack_null()
			}
		}
		Bool {
			p.pack_bool(v.value)
		}
		Null {
			p.pack_null()
		}
		Undefined {
			p.pack_undefined()
		}
		FloatNum {
			match v.bits {
				.half {
					// NaN/±Inf bypass the lossless check (NaN != NaN
					// breaks the f32 round-trip equality test).
					if math.is_nan(v.value) {
						p.pack_float16_bits(half_qnan_bits)
					} else if math.is_inf(v.value, 1) {
						p.pack_float16_bits(half_pos_inf_bits)
					} else if math.is_inf(v.value, -1) {
						p.pack_float16_bits(half_neg_inf_bits)
					} else {
						bits16, ok := f64_to_half(v.value)
						if ok {
							p.pack_float16_bits(bits16)
						} else {
							p.pack_float64(v.value)
						}
					}
				}
				.single {
					p.pack_float32(f32(v.value))
				}
				.double {
					p.pack_float64(v.value)
				}
				.@none {
					p.pack_float(v.value)
				}
			}
		}
		Simple {
			p.pack_simple(v.value) or {}
		}
	}
}

// pack_map_canonical sorts pairs by encoded-key bytes per RFC 8949
// §4.2.1 (length-first lexicographic, "bytewise lexicographic of the
// deterministic encodings of the keys") before emitting them.
fn (mut p Packer) pack_map_canonical(pairs []MapPair) {
	if pairs.len == 0 {
		return
	}
	// Encode each key once, sort indices by the encoded key bytes, then emit.
	mut encoded_keys := [][]u8{cap: pairs.len}
	for pair in pairs {
		mut sub := new_packer(EncodeOpts{ initial_cap: 16, canonical: true })
		sub.pack_value(pair.key)
		encoded_keys << sub.bytes().clone()
	}
	mut idx := []int{len: pairs.len, init: index}
	idx.sort_with_compare(fn [encoded_keys] (a &int, b &int) int {
		return compare_canonical_keys(encoded_keys[*a], encoded_keys[*b])
	})
	for i in idx {
		p.reserve(encoded_keys[i].len)
		unsafe { p.buf.push_many(encoded_keys[i].data, encoded_keys[i].len) }
		p.pack_value(pairs[i].value)
	}
}

// compare_canonical_keys orders byte slices by length first, then
// bytewise; this matches RFC 8949 §4.2.1 "Core Deterministic Encoding".
@[direct_array_access]
fn compare_canonical_keys(a []u8, b []u8) int {
	if a.len != b.len {
		return if a.len < b.len { -1 } else { 1 }
	}
	for i in 0 .. a.len {
		if a[i] != b[i] {
			return if a[i] < b[i] { -1 } else { 1 }
		}
	}
	return 0
}

// --------------------------------------------------------------------
// Module-level convenience wrappers
// --------------------------------------------------------------------

// encode_value emits a `Value` tree to a fresh byte slice with default opts.
pub fn encode_value(v Value, opts EncodeOpts) []u8 {
	mut p := new_packer(opts)
	p.pack_value(v)
	return p.bytes().clone()
}

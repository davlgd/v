module cbor

import time

// Generic comptime-driven encoder/decoder. The pack[T] / unpack[T]
// methods below dispatch on T at compile time, so each call site
// monomorphises into straight-line code with no runtime type tests.
//
// Supported targets:
//   * bool, all signed/unsigned integer widths, f32, f64
//   * string (text), []u8 (byte string), enums (encoded as int)
//   * `$array` (any V array) and `$map` (only `map[string]V` decodable
//     directly; encoder accepts any `$map`)
//   * `$struct` (encoded as a string-keyed map; honours
//     `@[cbor: 'alt']`, `@[skip]`, `@[cbor: '-']`, optional fields)
//   * `time.Time` — encoded as tag 1 (epoch seconds, integer) on encode;
//     accepts tag 0 (RFC 3339 text) or tag 1 on decode.
//   * `RawMessage`, `Value`, `Marshaler`/`Unmarshaler` implementers.

// pack encodes `val` into the packer's buffer using compile-time dispatch.
@[inline]
pub fn (mut p Packer) pack[T](val T) ! {
	$if T is RawMessage {
		p.pack_raw(val)
	} $else $if T is Marshaler {
		bytes := val.to_cbor()
		if bytes.len > 0 {
			p.reserve(bytes.len)
			unsafe { p.buf.push_many(bytes.data, bytes.len) }
		}
	} $else $if T is Value {
		p.pack_value(val)
	} $else $if T is time.Time {
		p.pack_tag(tag_epoch)
		p.pack_int(val.unix())
	} $else $if T is string {
		p.pack_text(val)
	} $else $if T is bool {
		p.pack_bool(val)
	} $else $if T is i8 {
		p.pack_int(i64(val))
	} $else $if T is i16 {
		p.pack_int(i64(val))
	} $else $if T is int {
		p.pack_int(i64(val))
	} $else $if T is i32 {
		p.pack_int(i64(val))
	} $else $if T is i64 {
		p.pack_int(val)
	} $else $if T is u8 {
		p.pack_uint(u64(val))
	} $else $if T is u16 {
		p.pack_uint(u64(val))
	} $else $if T is u32 {
		p.pack_uint(u64(val))
	} $else $if T is u64 {
		p.pack_uint(val)
	} $else $if T is f32 {
		p.pack_float(f64(val))
	} $else $if T is f64 {
		p.pack_float(val)
	} $else $if T is $enum {
		p.pack_int(i64(val))
	} $else $if T is []u8 {
		p.pack_bytes(val)
	} $else $if T is $array {
		p.pack_array_header(u64(val.len))
		for item in val {
			p.pack(item)!
		}
	} $else $if T is $map {
		p.pack_map_header(u64(val.len))
		if p.opts.canonical && val.len > 1 {
			mut encoded_keys := [][]u8{cap: val.len}
			mut encoded_vals := [][]u8{cap: val.len}
			for k, item in val {
				mut ksub := new_packer(EncodeOpts{ initial_cap: 16, canonical: true })
				ksub.pack(k)!
				encoded_keys << ksub.bytes().clone()
				mut vsub := new_packer(EncodeOpts{ initial_cap: 16, canonical: true })
				vsub.pack(item)!
				encoded_vals << vsub.bytes().clone()
			}
			mut idx := []int{len: val.len, init: index}
			idx.sort_with_compare(fn [encoded_keys] (a &int, b &int) int {
				return compare_canonical_keys(encoded_keys[*a], encoded_keys[*b])
			})
			for i in idx {
				p.reserve(encoded_keys[i].len + encoded_vals[i].len)
				unsafe {
					p.buf.push_many(encoded_keys[i].data, encoded_keys[i].len)
					p.buf.push_many(encoded_vals[i].data, encoded_vals[i].len)
				}
			}
		} else {
			for k, item in val {
				p.pack(k)!
				p.pack(item)!
			}
		}
	} $else $if T is $struct {
		mut strategy := ''
		$for attr in T.attributes {
			if attr.name == 'cbor_rename_all' {
				strategy = attr.arg
			}
		}
		mut field_count := 0
		$for field in T.fields {
			if !cbor_field_skipped(field) {
				field_count++
			}
		}
		p.pack_map_header(u64(field_count))
		if p.opts.canonical && field_count > 1 {
			// RFC 8949 §4.2.1: deterministic encoding requires keys to
			// be ordered by their encoded byte form, not by struct
			// declaration. Encode each (key, value) pair to a sub-buffer,
			// sort, then splice — same shape as the $map branch above.
			mut encoded_keys := [][]u8{cap: field_count}
			mut encoded_vals := [][]u8{cap: field_count}
			$for field in T.fields {
				if !cbor_field_skipped(field) {
					mut key := cbor_field_key(field)
					if strategy != '' && !cbor_field_renamed(field) {
						key = cbor_rename(field.name, strategy)
					}
					mut ksub := new_packer(EncodeOpts{ initial_cap: 16, canonical: true })
					ksub.pack_text(key)
					encoded_keys << ksub.bytes().clone()
					mut vsub := new_packer(EncodeOpts{ initial_cap: 16, canonical: true })
					$if field.typ is $option {
						if val.$(field.name) == none {
							vsub.pack_null()
						} else {
							vsub.pack(get_value_from_optional(val.$(field.name)))!
						}
					} $else {
						vsub.pack(val.$(field.name))!
					}
					encoded_vals << vsub.bytes().clone()
				}
			}
			mut idx := []int{len: field_count, init: index}
			idx.sort_with_compare(fn [encoded_keys] (a &int, b &int) int {
				return compare_canonical_keys(encoded_keys[*a], encoded_keys[*b])
			})
			for i in idx {
				p.reserve(encoded_keys[i].len + encoded_vals[i].len)
				unsafe {
					p.buf.push_many(encoded_keys[i].data, encoded_keys[i].len)
					p.buf.push_many(encoded_vals[i].data, encoded_vals[i].len)
				}
			}
		} else {
			$for field in T.fields {
				if !cbor_field_skipped(field) {
					mut key := cbor_field_key(field)
					if strategy != '' && !cbor_field_renamed(field) {
						key = cbor_rename(field.name, strategy)
					}
					p.pack_text(key)
					$if field.typ is $option {
						if val.$(field.name) == none {
							p.pack_null()
						} else {
							p.pack(get_value_from_optional(val.$(field.name)))!
						}
					} $else {
						p.pack(val.$(field.name))!
					}
				}
			}
		}
	} $else {
		p.pack_null()
	}
}

// get_value_from_optional unwraps an Option<T> known to be `Some`.
// Its signature exists solely so V's generic inferrer can pick up the
// inner T at the comptime call site.
fn get_value_from_optional[T](val ?T) T {
	return val or { T{} }
}

// unpack reads one CBOR value from the buffer and converts it to T.
@[inline]
pub fn (mut u Unpacker) unpack[T]() !T {
	$if T is RawMessage {
		return u.unpack_raw()!
	} $else $if T is Unmarshaler {
		start := u.pos
		u.skip_value()!
		mut v := T{}
		v.from_cbor(u.data[start..u.pos])!
		return v
	} $else $if T is Value {
		return u.unpack_value()!
	} $else $if T is time.Time {
		return u.unpack_time()!
	} $else $if T is string {
		return u.unpack_text()!
	} $else $if T is bool {
		// Accept null as false-equivalent? No — strict by default.
		return u.unpack_bool()!
	} $else $if T is i8 {
		v := u.unpack_int()!
		if v < -128 || v > 127 {
			return int_range(u.pos, 'i8', v.str())
		}
		return i8(v)
	} $else $if T is i16 {
		v := u.unpack_int()!
		if v < -32_768 || v > 32_767 {
			return int_range(u.pos, 'i16', v.str())
		}
		return i16(v)
	} $else $if T is int {
		v := u.unpack_int()!
		if v < -2_147_483_648 || v > 2_147_483_647 {
			return int_range(u.pos, 'int', v.str())
		}
		return int(v)
	} $else $if T is i32 {
		v := u.unpack_int()!
		if v < -2_147_483_648 || v > 2_147_483_647 {
			return int_range(u.pos, 'i32', v.str())
		}
		return i32(v)
	} $else $if T is i64 {
		return u.unpack_int()!
	} $else $if T is u8 {
		v := u.unpack_int()!
		if v < 0 || v > 255 {
			return int_range(u.pos, 'u8', v.str())
		}
		return u8(v)
	} $else $if T is u16 {
		v := u.unpack_int()!
		if v < 0 || v > 65_535 {
			return int_range(u.pos, 'u16', v.str())
		}
		return u16(v)
	} $else $if T is u32 {
		v := u.unpack_int()!
		if v < 0 || v > 4_294_967_295 {
			return int_range(u.pos, 'u32', v.str())
		}
		return u32(v)
	} $else $if T is u64 {
		neg, mag := u.unpack_int_full()!
		if neg {
			return int_range(u.pos, 'u64', '-1 - ${mag}')
		}
		return mag
	} $else $if T is f32 {
		return f32(u.unpack_float()!)
	} $else $if T is f64 {
		return u.unpack_float()!
	} $else $if T is $enum {
		v := int(u.unpack_int()!)
		return unsafe { T(v) }
	} $else $if T is []u8 {
		return u.unpack_bytes()!
	} $else $if T is $array {
		mut out := T{}
		u.unpack_array_into(mut out)!
		return out
	} $else $if T is $map {
		mut out := T{}
		read_pairs_into_helper(mut u, mut out)!
		return out
	} $else $if T is $struct {
		mut result := T{}
		u.unpack_struct_into(mut result)!
		return result
	} $else {
		return error('cbor: unsupported target type')
	}
}

fn (mut u Unpacker) unpack_array_into[E](mut out []E) ! {
	hdr := u.unpack_array_header()!
	if hdr < 0 {
		// Indefinite.
		for {
			if u.peek_break() {
				u.pos++
				break
			}
			out << u.unpack[E]()!
		}
		return
	}
	for _ in 0 .. hdr {
		out << u.unpack[E]()!
	}
}

// read_pairs_into_helper is a standalone (non-method) generic function;
// V's generic-method dispatch can drop the second type parameter when
// invoked from a comptime $map branch, while the standalone form
// monomorphises correctly.
fn read_pairs_into_helper[K, V](mut u Unpacker, mut out map[K]V) ! {
	hdr := u.unpack_map_header()!
	if hdr < 0 {
		for {
			if u.peek_break() {
				u.pos++
				break
			}
			key := u.unpack[K]()!
			val := u.unpack[V]()!
			if u.opts.deny_duplicate_keys && key in out {
				return malformed(u.pos, 'duplicate map key')
			}
			out[key] = val
		}
		return
	}
	for _ in 0 .. hdr {
		key := u.unpack[K]()!
		val := u.unpack[V]()!
		if u.opts.deny_duplicate_keys && key in out {
			return malformed(u.pos, 'duplicate map key')
		}
		out[key] = val
	}
}

fn (mut u Unpacker) unpack_struct_into[T](mut result T) ! {
	mut strategy := ''
	$for attr in T.attributes {
		if attr.name == 'cbor_rename_all' {
			strategy = attr.arg
		}
	}
	hdr := u.unpack_map_header()!
	indef := hdr < 0
	mut remaining := if indef { i64(-1) } else { hdr }
	for {
		if indef {
			if u.peek_break() {
				u.pos++
				break
			}
		} else {
			if remaining == 0 {
				break
			}
			remaining--
		}
		key_ptr, key_len := u.read_text_view()!
		mut matched := false
		$for field in T.fields {
			if !cbor_field_skipped(field) {
				mut name := cbor_field_key(field)
				if strategy != '' && !cbor_field_renamed(field) {
					name = cbor_rename(field.name, strategy)
				}
				if !matched && key_len == name.len
					&& unsafe { C.memcmp(key_ptr, name.str, key_len) } == 0 {
					matched = true
					$if field.typ is $option {
						if u.pos < u.data.len && u.data[u.pos] == 0xf6 {
							u.pos++
							result.$(field.name) = none
						} else {
							mut inner := create_value_from_optional(result.$(field.name))
							u.unpack_into(mut inner)!
							result.$(field.name) = inner
						}
					} $else {
						u.unpack_into(mut result.$(field.name))!
					}
				}
			}
		}
		if !matched {
			start := u.pos
			u.skip_value()!
			if u.opts.deny_unknown_fields {
				return UnknownFieldError{
					pos:  start
					name: unsafe { tos(key_ptr, key_len) }
				}
			}
		}
	}
}

// read_text_view returns a (ptr, len) view into the underlying buffer
// for one definite-length text string. Avoids allocation when matching
// struct field names. Errors on indefinite-length text since we'd have
// to copy chunks anyway.
@[direct_array_access]
fn (mut u Unpacker) read_text_view() !(&u8, int) {
	start := u.pos
	b := u.read_byte()!
	major := b >> 5
	if major != 3 {
		u.pos = start
		return type_mismatch(start, 'text', b)
	}
	info := b & 0x1f
	if info == 31 {
		u.pos = start
		return error('cbor: indefinite-length text not supported as map key (decoder)')
	}
	size := u.read_arg(info)!
	if u.pos + int(size) > u.data.len {
		return eof_needing(u.pos, int(size), u.data.len - u.pos)
	}
	if u.opts.validate_utf8 {
		if !u.is_utf8_at(u.pos, int(size)) {
			return InvalidUtf8Error{
				pos: u.pos
			}
		}
	}
	ptr := unsafe { &u8(u.data.data) + u.pos }
	u.pos += int(size)
	return ptr, int(size)
}

@[direct_array_access; inline]
fn (u &Unpacker) is_utf8_at(start int, size int) bool {
	if size == 0 {
		return true
	}
	return utf8_validate_slice(u.data, start, size)
}

// utf8_validate_slice runs the standard UTF-8 validator on a slice
// without making an intermediate copy. Mirrors the FSM used by
// `vlib/encoding/utf8/utf8_util.v`. The 8-byte SWAR pre-scan turns a
// pure-ASCII payload (the common case: JSON-shaped keys, identifiers)
// into one load + one mask + one branch per 8 bytes.
@[direct_array_access]
fn utf8_validate_slice(data []u8, start int, size int) bool {
	mut i := start
	end := start + size
	for i < end {
		// 8-byte SWAR ASCII fast path: a pure-ASCII run skips the
		// per-byte FSM entirely. Triggers on every iteration so a single
		// non-ASCII rune doesn't disable the fast path for the rest.
		for i + 8 <= end {
			chunk := unsafe { *(&u64(&data[i])) }
			if chunk & 0x8080808080808080 != 0 {
				break
			}
			i += 8
		}
		if i >= end {
			break
		}
		c := data[i]
		if c < 0x80 {
			i++
			continue
		}
		mut n := 0
		if c & 0xe0 == 0xc0 {
			n = 2
		} else if c & 0xf0 == 0xe0 {
			n = 3
		} else if c & 0xf8 == 0xf0 {
			n = 4
		} else {
			return false
		}
		if i + n > end {
			return false
		}
		// Reject overlongs / surrogates / out-of-range.
		match n {
			2 {
				if c < 0xc2 {
					return false
				}
			}
			3 {
				b := data[i + 1]
				if c == 0xe0 && b < 0xa0 {
					return false
				}
				if c == 0xed && b > 0x9f {
					return false
				}
			}
			4 {
				b := data[i + 1]
				if c == 0xf0 && b < 0x90 {
					return false
				}
				if c == 0xf4 && b > 0x8f {
					return false
				}
				if c > 0xf4 {
					return false
				}
			}
			else {}
		}

		for k in 1 .. n {
			if data[i + k] & 0xc0 != 0x80 {
				return false
			}
		}
		i += n
	}
	return true
}

// create_value_from_optional returns a zero value of an Option's inner T.
// Exists so the comptime call site can infer T from a struct field.
fn create_value_from_optional[T](_val ?T) T {
	return T{}
}

// unpack_into fills the target through a mutable reference. The mut
// parameter exists so V's generic inferer picks up T from the
// `u.unpack_into(mut result.$(field.name))!` call site.
@[inline]
fn (mut u Unpacker) unpack_into[T](mut out T) ! {
	_ = out // vet's "unused parameter" check doesn't track write-only mut args
	out = u.unpack[T]()!
}

// --------------------------------------------------------------------
// time.Time decoding
// --------------------------------------------------------------------

fn (mut u Unpacker) unpack_time() !time.Time {
	start := u.pos
	b := u.read_byte()!
	major := b >> 5
	if major != 6 {
		u.pos = start
		return type_mismatch(start, 'time tag', b)
	}
	number := u.read_arg(b & 0x1f)!
	match number {
		0 {
			s := u.unpack_text()!
			return time.parse_iso8601(s) or {
				return malformed(start, 'invalid RFC 3339 timestamp: ${err}')
			}
		}
		1 {
			peek := u.peek_byte() or { return error('cbor: missing tag-1 content') }
			major2 := peek >> 5
			if major2 == 0 || major2 == 1 {
				secs := u.unpack_int()!
				return time.unix(secs)
			}
			f := u.unpack_float()!
			whole := i64(f)
			frac := f - f64(whole)
			ns := i64(frac * 1_000_000_000)
			return time.unix_nanosecond(whole, int(ns))
		}
		else {
			u.pos = start
			return malformed(start, 'unexpected tag ${number} for time.Time')
		}
	}
}

// --------------------------------------------------------------------
// Struct attribute helpers
// --------------------------------------------------------------------

fn cbor_field_skipped[F](field F) bool {
	for attr in field.attrs {
		if attr == 'skip' {
			return true
		}
		if attr.starts_with('cbor:') {
			if val := parse_cbor_attr(attr) {
				if val == '-' {
					return true
				}
			}
		}
	}
	return false
}

fn cbor_field_key[F](field F) string {
	for attr in field.attrs {
		if attr.starts_with('cbor:') {
			if val := parse_cbor_attr(attr) {
				if val != '-' && val != '' {
					return val
				}
			}
		}
	}
	return field.name
}

fn cbor_field_renamed[F](field F) bool {
	for attr in field.attrs {
		if attr.starts_with('cbor:') {
			if val := parse_cbor_attr(attr) {
				if val != '-' && val != '' {
					return true
				}
			}
		}
	}
	return false
}

fn cbor_rename(name string, strategy string) string {
	match strategy {
		'snake_case' { return cbor_to_snake(name) }
		'camelCase' { return cbor_to_camel(name) }
		'PascalCase' { return cbor_to_pascal(name) }
		'kebab-case' { return cbor_to_kebab(name) }
		'SCREAMING_SNAKE_CASE' { return cbor_to_snake(name).to_upper() }
		else { return name }
	}
}

fn cbor_to_snake(s string) string {
	mut out := []u8{cap: s.len + 4}
	for i, c in s {
		if c >= `A` && c <= `Z` {
			if i > 0 {
				out << `_`
			}
			out << u8(c + 32)
		} else {
			out << c
		}
	}
	return out.bytestr()
}

fn cbor_to_camel(s string) string {
	mut out := []u8{cap: s.len}
	mut upper_next := false
	for i, c in s {
		if c == `_` {
			upper_next = true
			continue
		}
		if upper_next && c >= `a` && c <= `z` {
			out << u8(c - 32)
			upper_next = false
		} else if i == 0 && c >= `A` && c <= `Z` {
			out << u8(c + 32)
		} else {
			out << c
		}
	}
	return out.bytestr()
}

fn cbor_to_pascal(s string) string {
	camel := cbor_to_camel(s)
	if camel.len == 0 {
		return camel
	}
	first := camel[0]
	if first >= `a` && first <= `z` {
		return u8(first - 32).ascii_str() + camel[1..]
	}
	return camel
}

fn cbor_to_kebab(s string) string {
	mut out := []u8{cap: s.len + 4}
	for i, c in s {
		if c >= `A` && c <= `Z` {
			if i > 0 {
				out << `-`
			}
			out << u8(c + 32)
		} else if c == `_` {
			out << `-`
		} else {
			out << c
		}
	}
	return out.bytestr()
}

fn parse_cbor_attr(attr string) ?string {
	idx := attr.index(':') or { return none }
	mut v := attr[idx + 1..].trim_space()
	if v.len >= 2 && ((v.starts_with("'") && v.ends_with("'"))
		|| (v.starts_with('"') && v.ends_with('"'))) {
		v = v[1..v.len - 1]
	}
	return v
}

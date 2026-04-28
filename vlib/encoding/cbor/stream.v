module cbor

import io

// Stream I/O wrappers over the standard `io.Reader` / `io.Writer`
// interfaces. Use these for files, sockets, pipes — anywhere the
// payload doesn't fit cleanly in a single `[]u8`.

// encode_to serialises `val` into an internal buffer, then writes the
// bytes to `w` in a loop until everything is accepted. Errors on the
// first I/O failure.
pub fn encode_to[T](val T, mut w io.Writer, opts EncodeOpts) ! {
	bytes := encode[T](val, opts)!
	mut written := 0
	for written < bytes.len {
		n := w.write(bytes[written..])!
		if n == 0 {
			return error('cbor: writer stopped accepting bytes at ${written}/${bytes.len}')
		}
		written += n
	}
}

// decode_from reads bytes from `r` until EOF (or until
// `DecodeOpts.max_stream_bytes` is hit) and decodes a single top-level
// value. For multi-value streams, use `Unpacker` directly on a
// pre-buffered slice.
//
// Always set `max_stream_bytes` on untrusted readers — otherwise a peer
// that never sends EOF blocks the call forever.
pub fn decode_from[T](mut r io.Reader, opts DecodeOpts) !T {
	if opts.max_stream_bytes <= 0 {
		data := io.read_all(reader: r, read_to_end_of_stream: true)!
		return decode[T](data, opts)!
	}
	mut buf := []u8{cap: 4096}
	for {
		if buf.len >= opts.max_stream_bytes {
			return error('cbor: stream exceeded max_stream_bytes (${opts.max_stream_bytes})')
		}
		slot_cap := opts.max_stream_bytes - buf.len
		slot_len := if slot_cap < 4096 { slot_cap } else { 4096 }
		mut slot := []u8{len: slot_len}
		n := r.read(mut slot) or { break }
		if n == 0 {
			break
		}
		buf << slot[..n]
	}
	return decode[T](buf, opts)!
}

// pack_to is the streaming sibling of `encode_to`, for users who built
// their payload manually via the `Packer` API.
pub fn (mut p Packer) pack_to(mut w io.Writer) ! {
	bytes := p.bytes()
	mut written := 0
	for written < bytes.len {
		n := w.write(bytes[written..])!
		if n == 0 {
			return error('cbor: writer stopped at ${written}/${bytes.len}')
		}
		written += n
	}
}

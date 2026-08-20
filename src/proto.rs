//! A minimal protobuf wire-format reader/writer.
//!
//! Google Authenticator's export payload is a protobuf message, but pulling in
//! `prost` + `protoc` for five fields is not worth the build-time dependency —
//! `gaexport` must build with nothing but a Rust toolchain. This module
//! implements just the slice of the wire format the payload uses:
//! varints, length-delimited fields, and unknown-field skipping.

use anyhow::{bail, Result};

pub const WIRE_VARINT: u8 = 0;
pub const WIRE_I64: u8 = 1;
pub const WIRE_LEN: u8 = 2;
pub const WIRE_I32: u8 = 5;

/// Reader over a protobuf-encoded byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Reads the next `(field_number, wire_type)` pair.
    pub fn tag(&mut self) -> Result<(u32, u8)> {
        let key = self.varint()?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        if field == 0 {
            bail!("protobuf: field number 0 is invalid");
        }
        Ok((field, wire))
    }

    pub fn varint(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            if self.pos >= self.buf.len() {
                bail!("protobuf: truncated varint at offset {}", self.pos);
            }
            let byte = self.buf[self.pos];
            self.pos += 1;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                bail!("protobuf: varint overflows 64 bits");
            }
        }
    }

    /// Reads a length-delimited field body.
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.varint()? as usize;
        let end = self
            .pos
            .checked_add(len)
            .filter(|e| *e <= self.buf.len())
            .ok_or_else(|| anyhow::anyhow!("protobuf: length-delimited field runs past end"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }

    /// Skips a field whose number we do not know, so unknown/newer fields in a
    /// payload never make the whole export fail.
    pub fn skip(&mut self, wire: u8) -> Result<()> {
        match wire {
            WIRE_VARINT => {
                self.varint()?;
            }
            WIRE_I64 => self.advance(8)?,
            WIRE_LEN => {
                self.bytes()?;
            }
            WIRE_I32 => self.advance(4)?,
            other => bail!("protobuf: unsupported wire type {other}"),
        }
        Ok(())
    }

    fn advance(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            bail!("protobuf: truncated fixed-width field");
        }
        self.pos += n;
        Ok(())
    }
}

/// Writer producing protobuf-encoded bytes.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    pub fn varint(&mut self, mut value: u64) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                self.buf.push(byte);
                return;
            }
            self.buf.push(byte | 0x80);
        }
    }

    fn tag(&mut self, field: u32, wire: u8) {
        self.varint((u64::from(field) << 3) | u64::from(wire));
    }

    /// Writes a varint field. Skips the field entirely when `value == 0`,
    /// matching proto3's default-value omission.
    pub fn uint_field(&mut self, field: u32, value: u64) {
        if value == 0 {
            return;
        }
        self.tag(field, WIRE_VARINT);
        self.varint(value);
    }

    /// Writes an `int32`/`int64` field (two's-complement varint for negatives).
    pub fn int_field(&mut self, field: u32, value: i64) {
        if value == 0 {
            return;
        }
        self.tag(field, WIRE_VARINT);
        self.varint(value as u64);
    }

    pub fn bytes_field(&mut self, field: u32, value: &[u8]) {
        if value.is_empty() {
            return;
        }
        self.tag(field, WIRE_LEN);
        self.varint(value.len() as u64);
        self.buf.extend_from_slice(value);
    }

    pub fn string_field(&mut self, field: u32, value: &str) {
        self.bytes_field(field, value.as_bytes());
    }

    /// Writes an embedded message, even when its body is empty.
    pub fn message_field(&mut self, field: u32, body: &[u8]) {
        self.tag(field, WIRE_LEN);
        self.varint(body.len() as u64);
        self.buf.extend_from_slice(body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for value in [0u64, 1, 127, 128, 300, 16_384, u32::MAX as u64, u64::MAX] {
            let mut w = Writer::new();
            w.varint(value);
            let bytes = w.into_inner();
            let mut r = Reader::new(&bytes);
            assert_eq!(r.varint().unwrap(), value);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn negative_int32_uses_ten_byte_varint() {
        let mut w = Writer::new();
        w.int_field(5, -1);
        let bytes = w.into_inner();
        let mut r = Reader::new(&bytes);
        let (field, wire) = r.tag().unwrap();
        assert_eq!((field, wire), (5, WIRE_VARINT));
        assert_eq!(r.varint().unwrap() as i64, -1);
    }

    #[test]
    fn unknown_fields_are_skipped() {
        let mut w = Writer::new();
        w.string_field(9, "unknown");
        w.uint_field(2, 42);
        let bytes = w.into_inner();
        let mut r = Reader::new(&bytes);
        let mut version = 0;
        while !r.is_empty() {
            match r.tag().unwrap() {
                (2, WIRE_VARINT) => version = r.varint().unwrap(),
                (_, wire) => r.skip(wire).unwrap(),
            }
        }
        assert_eq!(version, 42);
    }

    #[test]
    fn truncated_input_errors() {
        let mut r = Reader::new(&[0x92]);
        assert!(r.varint().is_err());
        let mut r = Reader::new(&[0x0a, 0x05, 0x01]);
        let (_f, w) = r.tag().unwrap();
        assert_eq!(w, WIRE_LEN);
        assert!(r.bytes().is_err());
    }
}

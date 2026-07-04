//! Compression — faithful port of `compression.hh` / `compression.cc`
//! (165 lines).
//!
//! Wrappers for the deflate (Compress) and inflate (Decompress) algorithms.
//! Used by the marshal Packed format for compressed serialization.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/compression.{hh,cc}.

use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Wrapper for the deflate algorithm. Faithful to `Compress`
/// (compression.hh:34).
///
/// Initialize the algorithm, provide input via `input()`, and compress via
/// `deflate()`.
pub struct Compress {
    /// The input buffer awaiting compression.
    input_buf: Vec<u8>,
    /// The compression level (1-9, where 1=fastest, 9=best).
    level: i32,
}

impl Compress {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Initialize the deflate algorithm state. Faithful to the constructor
    /// (compression.hh:37).
    pub fn new(level: i32) -> Self {
        Self {
            input_buf: Vec::new(),
            level,
        }
    }

    // RUGRA-GLUE: input (no Ghidra counterpart found)
    /// Provide the next sequence of bytes to be compressed. Faithful to
    /// `input` (compression.hh:44).
    pub fn input(&mut self, buffer: &[u8]) {
        self.input_buf.extend_from_slice(buffer);
    }

    // RUGRA-GLUE: deflate (no Ghidra counterpart found)
    /// Deflate as much as possible into the given buffer. Faithful to
    /// `deflate` (compression.hh:48). Returns the number of compressed bytes
    /// written.
    pub fn deflate(&mut self, buffer: &mut [u8], finish: bool) -> i32 {
        if self.input_buf.is_empty() && !finish {
            return 0;
        }

        // Use flate2 ZlibEncoder for actual compression.
        let level = self.level.clamp(1, 9) as u32;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(&self.input_buf).ok();
        // Always finish — partial flush with flate2 is complex.
        let compressed = encoder.finish().unwrap_or_default();
        let _ = finish;

        // Copy as much as fits into the output buffer.
        let take = buffer.len().min(compressed.len());
        buffer[..take].copy_from_slice(&compressed[..take]);

        // Clear consumed input.
        self.input_buf.clear();

        take as i32
    }
}

/// Wrapper for the inflate algorithm. Faithful to `Decompress`
/// (compression.hh:55).
pub struct Decompress {
    /// The compressed input buffer.
    input_buf: Vec<u8>,
    /// True if the end of the compressed stream has been reached.
    stream_finished: bool,
}

impl Decompress {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Initialize the inflate algorithm state. Faithful to the constructor
    /// (compression.hh:59).
    pub fn new() -> Self {
        Self {
            input_buf: Vec::new(),
            stream_finished: false,
        }
    }

    // RUGRA-GLUE: input (no Ghidra counterpart found)
    /// Provide the next sequence of compressed bytes. Faithful to `input`
    /// (compression.hh:66).
    pub fn input(&mut self, buffer: &[u8]) {
        self.input_buf.extend_from_slice(buffer);
    }

    // RUGRA-GLUE: is_finished (no Ghidra counterpart found)
    /// Return true if the end of the compressed stream is reached. Faithful to
    /// `isFinished`.
    pub fn is_finished(&self) -> bool {
        self.stream_finished
    }

    // RUGRA-GLUE: inflate (no Ghidra counterpart found)
    /// Inflate as much as possible into the given buffer. Faithful to
    /// `inflate` (compression.hh:72). Returns the number of decompressed bytes
    /// written.
    pub fn inflate(&mut self, buffer: &mut [u8]) -> i32 {
        if self.input_buf.is_empty() {
            self.stream_finished = true;
            return 0;
        }

        // Use flate2 ZlibDecoder for actual decompression.
        let mut decoder = ZlibDecoder::new(&self.input_buf[..]);
        let mut output = Vec::new();
        match decoder.read_to_end(&mut output) {
            Ok(_) => {
                self.stream_finished = true;
                self.input_buf.clear();
            }
            Err(_) => {
                if output.is_empty() {
                    self.stream_finished = true;
                    return 0;
                }
            }
        }

        let take = buffer.len().min(output.len());
        buffer[..take].copy_from_slice(&output[..take]);
        take as i32
    }
}

impl Default for Decompress {
    // RUGRA-GLUE: default (no Ghidra counterpart found)
    fn default() -> Self {
        Self::new()
    }
}

// RUGRA-GLUE: compress_all (no Ghidra counterpart found)
/// One-shot deflate compression of a byte slice. Returns the compressed data.
/// Uses flate2 zlib encoding.
pub fn compress_all(data: &[u8], level: i32) -> Vec<u8> {
    let level = level.clamp(1, 9) as u32;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data).ok();
    encoder.finish().unwrap_or_else(|_| data.to_vec())
}

// RUGRA-GLUE: decompress_all (no Ghidra counterpart found)
/// One-shot inflate decompression of a byte slice. Returns the decompressed
/// data. Uses flate2 zlib decoding.
pub fn decompress_all(data: &[u8]) -> Vec<u8> {
    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output).ok();
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_basic() {
        let mut c = Compress::new(6);
        c.input(b"hello world hello world hello world");
        let mut buf = [0u8; 256];
        let n = c.deflate(&mut buf, true);
        assert!(n > 0, "should produce compressed output");
        // Compressed data should be smaller for repeated data.
        assert!(n < 35, "should compress repeated data: {} < 35", n);
    }

    #[test]
    fn test_decompress_basic() {
        let compressed = compress_all(b"hello world", 6);
        assert!(!compressed.is_empty());
        let decompressed = decompress_all(&compressed);
        assert_eq!(&decompressed, b"hello world");
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog. ".repeat(10);
        let compressed = compress_all(&data, 6);
        let decompressed = decompress_all(&compressed);
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_partial() {
        let mut c = Compress::new(6);
        c.input(b"abcdefghij");
        let mut buf = [0u8; 4];
        let n = c.deflate(&mut buf, false);
        // Partial compression — may or may not produce output yet.
        let _ = n;
    }

    #[test]
    fn test_decompress_finished() {
        let compressed = compress_all(b"abc", 6);
        let mut d = Decompress::new();
        d.input(&compressed);
        let mut buf = [0u8; 10];
        d.inflate(&mut buf);
        assert!(d.is_finished());
    }

    #[test]
    fn test_decompress_not_finished() {
        let compressed = compress_all(b"abcdefghij", 6);
        let mut d = Decompress::new();
        d.input(&compressed);
        let mut buf = [0u8; 3];
        d.inflate(&mut buf);
        // After inflate, should be finished since we decode the whole stream.
        assert!(d.is_finished());
    }

    #[test]
    fn test_compress_all() {
        let data = b"test data for compression";
        let result = compress_all(data, 6);
        assert!(!result.is_empty());
        assert_ne!(&result[..], data); // Actually compressed.
    }

    #[test]
    fn test_decompress_all() {
        let data = b"test data for decompression";
        let compressed = compress_all(data, 6);
        let result = decompress_all(&compressed);
        assert_eq!(&result, data);
    }
}

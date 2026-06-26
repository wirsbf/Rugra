//! Compression — faithful port of `compression.hh` / `compression.cc`
//! (165 lines).
//!
//! Wrappers for the deflate (Compress) and inflate (Decompress) algorithms.
//! Used by the marshal Packed format for compressed serialization.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/compression.{hh,cc}.

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
    /// Initialize the deflate algorithm state. Faithful to the constructor
    /// (compression.hh:37).
    pub fn new(level: i32) -> Self {
        Self {
            input_buf: Vec::new(),
            level,
        }
    }

    /// Provide the next sequence of bytes to be compressed. Faithful to
    /// `input` (compression.hh:44).
    pub fn input(&mut self, buffer: &[u8]) {
        self.input_buf.extend_from_slice(buffer);
    }

    /// Deflate as much as possible into the given buffer. Faithful to
    /// `deflate` (compression.hh:48).
    ///
    /// NOTE: This is a stub that returns the uncompressed data. Full deflate
    /// requires the `flate2` crate (L3 gap).
    pub fn deflate(&mut self, buffer: &mut [u8], finish: bool) -> i32 {
        let take = buffer.len().min(self.input_buf.len());
        buffer[..take].copy_from_slice(&self.input_buf[..take]);
        self.input_buf.drain(..take);
        if finish {
            // All data flushed.
        }
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
    /// Initialize the inflate algorithm state. Faithful to the constructor
    /// (compression.hh:59).
    pub fn new() -> Self {
        Self {
            input_buf: Vec::new(),
            stream_finished: false,
        }
    }

    /// Provide the next sequence of compressed bytes. Faithful to `input`
    /// (compression.hh:66).
    pub fn input(&mut self, buffer: &[u8]) {
        self.input_buf.extend_from_slice(buffer);
    }

    /// Return true if the end of the compressed stream is reached. Faithful to
    /// `isFinished`.
    pub fn is_finished(&self) -> bool {
        self.stream_finished
    }

    /// Inflate as much as possible into the given buffer. Faithful to
    /// `inflate` (compression.hh:72).
    ///
    /// NOTE: This is a stub that returns the data as-is. Full inflate requires
    /// the `flate2` crate (L3 gap).
    pub fn inflate(&mut self, buffer: &mut [u8]) -> i32 {
        let take = buffer.len().min(self.input_buf.len());
        buffer[..take].copy_from_slice(&self.input_buf[..take]);
        self.input_buf.drain(..take);
        if self.input_buf.is_empty() {
            self.stream_finished = true;
        }
        take as i32
    }
}

impl Default for Decompress {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot deflate compression of a byte slice. Returns the compressed data.
/// NOTE: Stub (no actual compression). L3 gap: requires flate2.
pub fn compress_all(data: &[u8], _level: i32) -> Vec<u8> {
    data.to_vec()
}

/// One-shot inflate decompression of a byte slice. Returns the decompressed
/// data. NOTE: Stub (no actual decompression). L3 gap: requires flate2.
pub fn decompress_all(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_basic() {
        let mut c = Compress::new(6);
        c.input(b"hello world");
        let mut buf = [0u8; 256];
        let n = c.deflate(&mut buf, true);
        assert_eq!(n, 11); // Stub returns uncompressed.
        assert_eq!(&buf[..n as usize], b"hello world");
    }

    #[test]
    fn test_decompress_basic() {
        let mut d = Decompress::new();
        d.input(b"hello");
        let mut buf = [0u8; 256];
        let n = d.inflate(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..n as usize], b"hello");
        assert!(d.is_finished());
    }

    #[test]
    fn test_compress_partial() {
        let mut c = Compress::new(6);
        c.input(b"abcdefghij");
        let mut buf = [0u8; 4];
        let n = c.deflate(&mut buf, false);
        assert_eq!(n, 4);
        assert_eq!(&buf, b"abcd");
        // Remaining data — use a larger buffer.
        let mut buf2 = [0u8; 10];
        let n2 = c.deflate(&mut buf2, true);
        assert_eq!(n2, 6);
        assert_eq!(&buf2[..6], b"efghij");
    }

    #[test]
    fn test_decompress_finished() {
        let mut d = Decompress::new();
        d.input(b"abc");
        let mut buf = [0u8; 10];
        d.inflate(&mut buf);
        assert!(d.is_finished());
    }

    #[test]
    fn test_decompress_not_finished() {
        let mut d = Decompress::new();
        d.input(b"abcdefghij");
        let mut buf = [0u8; 3];
        d.inflate(&mut buf);
        assert!(!d.is_finished());
    }

    #[test]
    fn test_compress_all_stub() {
        let result = compress_all(b"test", 6);
        assert_eq!(result, b"test"); // Stub: no actual compression.
    }

    #[test]
    fn test_decompress_all_stub() {
        let result = decompress_all(b"test");
        assert_eq!(result, b"test"); // Stub: no actual decompression.
    }
}

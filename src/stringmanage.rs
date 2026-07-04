//! String management — faithful port of `stringmanage.hh` / `stringmanage.cc`
//! (477 lines).
//!
//! Classes for decoding and storing string data. Looks at data in the
//! loadimage to determine if it represents a "string". Decodes the string for
//! presentation in the output, and stores the decoded string until needed.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/stringmanage.{hh,cc}.

use crate::address::Address;
use crate::loadimage::LoadImage;
use std::collections::BTreeMap;

/// String data stored by StringManager. Faithful to `StringManager::StringData`
/// (stringmanage.hh:43).
#[derive(Debug, Clone, Default)]
pub struct StringData {
    /// True if the string is truncated.
    pub is_truncated: bool,
    /// UTF8 encoded string data.
    pub byte_data: Vec<u8>,
}

// Ghidra: stringmanage.hh:43 StringData::writeUtf8
/// Write a unicode codepoint as UTF8 to a byte vector. Faithful to
/// `StringManager::writeUtf8` (stringmanage.cc:124).
pub fn write_utf8(out: &mut Vec<u8>, codepoint: i32) {
    if codepoint < 0 {
        return;
    }
    if codepoint < 128 {
        out.push(codepoint as u8);
        return;
    }
    let bits = crate::address::mostsigbit_set(codepoint as u64) + 1;
    if bits > 21 {
        return;
    }
    if bits < 12 {
        out.push(0xc0u8 ^ ((codepoint >> 6) as u8 & 0x1f));
        out.push(0x80u8 ^ (codepoint as u8 & 0x3f));
    } else if bits < 17 {
        out.push(0xe0u8 ^ ((codepoint >> 12) as u8 & 0x0f));
        out.push(0x80u8 ^ ((codepoint >> 6) as u8 & 0x3f));
        out.push(0x80u8 ^ (codepoint as u8 & 0x3f));
    } else {
        out.push(0xf0u8 ^ ((codepoint >> 18) as u8 & 0x07));
        out.push(0x80u8 ^ ((codepoint >> 12) as u8 & 0x3f));
        out.push(0x80u8 ^ ((codepoint >> 6) as u8 & 0x3f));
        out.push(0x80u8 ^ (codepoint as u8 & 0x3f));
    }
}

// Ghidra: stringmanage.hh:43 StringData::readUtf16
/// Read a UTF16 code point from a 2-byte array. Faithful to
/// `StringManager::readUtf16` (stringmanage.cc:297).
pub fn read_utf16(buf: &[u8], bigend: bool) -> i32 {
    if bigend {
        ((buf[0] as i32) << 8) + buf[1] as i32
    } else {
        ((buf[1] as i32) << 8) + buf[0] as i32
    }
}

// Ghidra: stringmanage.hh:43 StringData::getCodepoint
/// Extract the next unicode codepoint from a byte array. Faithful to
/// `StringManager::getCodepoint` (stringmanage.cc:347).
///
/// Returns `(codepoint, bytes_consumed)` or `(-1, skip)` if invalid.
/// `charsize` is 1 for UTF8, 2 for UTF16, 4 for UTF32.
pub fn get_codepoint(buf: &[u8], charsize: i32, bigend: bool) -> (i32, i32) {
    if buf.is_empty() {
        return (-1, charsize);
    }
    let codepoint;
    let skip;
    if charsize == 2 {
        // UTF-16
        if buf.len() < 2 {
            return (-1, 2);
        }
        codepoint = read_utf16(buf, bigend);
        skip = 2;
        if (0xD800..=0xDBFF).contains(&codepoint) {
            // High surrogate.
            if buf.len() < 4 {
                return (-1, 4);
            }
            let trail = read_utf16(&buf[2..], bigend);
            if !(0xDC00..=0xDFFF).contains(&trail) {
                return (-1, 4);
            }
            let combined = (codepoint << 10) + trail + (0x10000 - (0xD800 << 10) - 0xDC00);
            return (combined, 4);
        }
        if (0xDC00..=0xDFFF).contains(&codepoint) {
            return (-1, 2); // Trail before high.
        }
    } else if charsize == 1 {
        // UTF-8
        let val = buf[0] as i32;
        if (val & 0x80) == 0 {
            return (val, 1);
        } else if (val & 0xe0) == 0xc0 {
            if buf.len() < 2 {
                return (-1, 2);
            }
            let val2 = buf[1] as i32;
            if (val2 & 0xc0) != 0x80 {
                return (-1, 2);
            }
            return (((val & 0x1f) << 6) | (val2 & 0x3f), 2);
        } else if (val & 0xf0) == 0xe0 {
            if buf.len() < 3 {
                return (-1, 3);
            }
            let val2 = buf[1] as i32;
            let val3 = buf[2] as i32;
            if (val2 & 0xc0) != 0x80 || (val3 & 0xc0) != 0x80 {
                return (-1, 3);
            }
            return (((val & 0x0f) << 12) | ((val2 & 0x3f) << 6) | (val3 & 0x3f), 3);
        } else if (val & 0xf8) == 0xf0 {
            if buf.len() < 4 {
                return (-1, 4);
            }
            let val2 = buf[1] as i32;
            let val3 = buf[2] as i32;
            let val4 = buf[3] as i32;
            if (val2 & 0xc0) != 0x80 || (val3 & 0xc0) != 0x80 || (val4 & 0xc0) != 0x80 {
                return (-1, 4);
            }
            return (
                ((val & 7) << 18) | ((val2 & 0x3f) << 12) | ((val3 & 0x3f) << 6) | (val4 & 0x3f),
                4,
            );
        } else {
            return (-1, 1);
        }
    } else if charsize == 4 {
        // UTF-32
        if buf.len() < 4 {
            return (-1, 4);
        }
        if bigend {
            codepoint = ((buf[0] as i32) << 24) + ((buf[1] as i32) << 16)
                + ((buf[2] as i32) << 8)
                + buf[3] as i32;
        } else {
            codepoint = ((buf[3] as i32) << 24) + ((buf[2] as i32) << 16)
                + ((buf[1] as i32) << 8)
                + buf[0] as i32;
        }
        skip = 4;
    } else {
        return (-1, charsize);
    }
    // Validate the codepoint.
    if codepoint >= 0xd800 {
        if codepoint > 0x10ffff {
            return (-1, skip);
        }
        if codepoint <= 0xdfff {
            return (-1, skip);
        }
    }
    (codepoint, skip)
}

// Ghidra: stringmanage.hh:43 StringData::checkCharacters
/// Check that the buffer contains valid bounded unicode. Faithful to
/// `StringManager::checkCharacters` (stringmanage.cc:324).
///
/// Returns the number of characters, or -1 if invalid.
pub fn check_characters(buf: &[u8], charsize: i32, bigend: bool) -> i32 {
    let mut i = 0;
    let mut count = 0;
    while i < buf.len() {
        let (codepoint, skip) = get_codepoint(&buf[i..], charsize, bigend);
        if codepoint < 0 {
            return -1;
        }
        if codepoint == 0 {
            break;
        }
        count += 1;
        i += skip as usize;
    }
    count
}

// Ghidra: stringmanage.hh:43 StringData::hasCharTerminator
/// Check for a unicode string terminator (null char) in the buffer. Faithful
/// to `StringManager::hasCharTerminator` (stringmanage.cc:277).
pub fn has_char_terminator(buffer: &[u8], charsize: usize) -> bool {
    let mut i = 0;
    while i + charsize <= buffer.len() {
        let mut is_terminator = true;
        for j in 0..charsize {
            if buffer[i + j] != 0 {
                is_terminator = false;
                break;
            }
        }
        if is_terminator {
            return true;
        }
        i += charsize;
    }
    false
}

// Ghidra: stringmanage.hh:43 StringData::writeUnicode
/// Write unicode buffer to UTF8 output. Faithful to
/// `StringManager::writeUnicode` (stringmanage.cc:36).
///
/// Returns true if the buffer is valid unicode.
pub fn write_unicode(
    out: &mut Vec<u8>,
    buffer: &[u8],
    charsize: i32,
    bigend: bool,
    maximum_chars: i32,
) -> bool {
    let mut i = 0;
    let mut count = 0;
    while i < buffer.len() {
        let (codepoint, skip) = get_codepoint(&buffer[i..], charsize, bigend);
        if codepoint < 0 {
            return false;
        }
        if codepoint == 0 {
            break;
        }
        write_utf8(out, codepoint);
        i += skip as usize;
        count += 1;
        if count >= maximum_chars {
            break;
        }
    }
    true
}

// Ghidra: stringmanage.hh:43 StringData::assignStringData
/// Assign string data. Faithful to `StringManager::assignStringData`
/// (stringmanage.cc:66).
pub fn assign_string_data(
    data: &mut StringData,
    buf: &[u8],
    charsize: i32,
    num_chars: i32,
    bigend: bool,
    maximum_chars: i32,
) {
    if charsize == 1 && num_chars < maximum_chars {
        data.byte_data.clear();
        data.byte_data.extend_from_slice(buf);
    } else {
        let mut s = Vec::new();
        if !write_unicode(&mut s, buf, charsize, bigend, maximum_chars) {
            return;
        }
        data.byte_data = s;
        data.byte_data.push(0); // Null terminator.
    }
    data.is_truncated = num_chars >= maximum_chars;
}

/// Storage for decoding and storing strings associated with an address.
/// Faithful to `StringManager` (stringmanage.hh:40).
pub struct StringManager {
    /// Map from address to string data.
    string_map: BTreeMap<u64, StringData>,
    /// Maximum characters in a string before truncating.
    maximum_chars: i32,
}

impl StringManager {
    // Ghidra: stringmanage.cc:108 StringManager::new
    /// Construct given the maximum number of characters. Faithful to the
    /// constructor (stringmanage.cc:108).
    pub fn new(max: i32) -> Self {
        Self {
            string_map: BTreeMap::new(),
            maximum_chars: max,
        }
    }

    // Ghidra: stringmanage.cc:108 StringManager::clear
    /// Clear out any cached strings. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.string_map.clear();
    }

    // Ghidra: stringmanage.cc:108 StringManager::getMaximumChars
    /// Get the maximum character count.
    pub fn get_maximum_chars(&self) -> i32 {
        self.maximum_chars
    }

    // Ghidra: stringmanage.cc:166 StringManager::isString
    /// Determine if data at the given address is a string. Faithful to
    /// `isString` (stringmanage.cc:166).
    pub fn is_string(&self, addr: Address) -> bool {
        self.string_map
            .get(&addr.as_u64())
            .map_or(false, |d| !d.byte_data.is_empty())
    }

    // Ghidra: stringmanage.cc:108 StringManager::getStringData
    /// Retrieve string data at the given address. Returns a clone of the
    /// cached data, or empty if not a string.
    pub fn get_string_data(&self, addr: Address) -> Option<&StringData> {
        self.string_map.get(&addr.as_u64())
    }

    // Ghidra: stringmanage.cc:108 StringManager::insertStringData
    /// Insert string data at the given address.
    pub fn insert_string_data(&mut self, addr: Address, data: StringData) {
        self.string_map.insert(addr.as_u64(), data);
    }

    // Ghidra: stringmanage.cc:108 StringManager::numStrings
    /// Number of cached strings.
    pub fn num_strings(&self) -> usize {
        self.string_map.len()
    }

    // Ghidra: stringmanage.cc:203 StringManager::encode
    /// Encode cached strings to a stream. Faithful to `StringManager::encode`
    /// (stringmanage.cc:203). Emits `<stringmanage>` with `<string>` children.
    pub fn encode(&self, encoder: &mut dyn crate::marshal::Encoder) {
        use crate::marshal::{AttributeId, ElementId};
        let sm_elem = ElementId::new("stringmanage", 0);
        let str_elem = ElementId::new("string", 0);
        let bytes_elem = ElementId::new("bytes", 0);
        let addr_elem = ElementId::new("addr", 0);
        encoder.open_element(&sm_elem);
        for (&addr_u64, data) in &self.string_map {
            encoder.open_element(&str_elem);
            // Address.
            encoder.open_element(&addr_elem);
            encoder.write_unsigned_integer(&AttributeId::new("space", 0), addr_u64);
            encoder.close_element(&addr_elem);
            // Bytes with truncation flag.
            encoder.open_element(&bytes_elem);
            encoder.write_bool(&AttributeId::new("trunc", 0), data.is_truncated);
            // Hex-encode the byte data.
            let hex: String = data.byte_data.iter().map(|b| format!("{b:02x} ")).collect();
            encoder.write_string(&AttributeId::new("content", 1), hex.trim());
            encoder.close_element(&bytes_elem);
            encoder.close_element(&str_elem);
        }
        encoder.close_element(&sm_elem);
    }

    // Ghidra: stringmanage.cc:231 StringManager::decode
    /// Restore string cache from a stream. Faithful to `StringManager::decode`
    /// (stringmanage.cc:230).
    pub fn decode(&mut self, decoder: &mut dyn crate::marshal::Decoder) {
        use crate::marshal::{AttributeId, ElementId};
        let sm_id = decoder.open_element();
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let elem_name = decoder.element_name(sub_id).unwrap_or_default();
            if elem_name != "string" {
                decoder.open_element();
                decoder.close_element_skipping(sub_id);
                continue;
            }
            decoder.open_element();
            // Read addr child.
            let addr_id = decoder.peek_element();
            let mut addr_u64 = 0u64;
            if addr_id != 0 {
                decoder.open_element();
                loop {
                    let aid = decoder.next_attribute_id();
                    if aid == 0 { break; }
                    if decoder.attribute_name(aid).as_deref() == Some("space") {
                        addr_u64 = decoder.read_unsigned_integer();
                    } else { let _ = decoder.read_string(); }
                }
                decoder.close_element(addr_id);
            }
            // Read bytes child.
            let bytes_id = decoder.peek_element();
            let mut is_truncated = false;
            let mut byte_data = Vec::new();
            if bytes_id != 0 {
                decoder.open_element();
                loop {
                    let aid = decoder.next_attribute_id();
                    if aid == 0 { break; }
                    match decoder.attribute_name(aid).as_deref() {
                        Some("trunc") => is_truncated = decoder.read_bool(),
                        Some("content") => {
                            let hex_str = decoder.read_string();
                            for chunk in hex_str.split_whitespace() {
                                if let Ok(b) = u8::from_str_radix(chunk, 16) {
                                    byte_data.push(b);
                                }
                            }
                        }
                        _ => { let _ = decoder.read_string(); }
                    }
                }
                decoder.close_element(bytes_id);
            }
            decoder.close_element(sub_id);
            self.string_map.insert(addr_u64, StringData {
                is_truncated,
                byte_data,
            });
        }
        decoder.close_element(sm_id);
    }
}

/// An implementation of StringManager that understands terminated unicode
/// strings (UTF8, UTF16, UTF32). Faithful to `StringManagerUnicode`
/// (stringmanage.hh:86).
pub struct StringManagerUnicode {
    /// The base string manager.
    pub manager: StringManager,
    /// The load image to read bytes from.
    loader: Option<std::sync::Arc<dyn LoadImage>>,
}

impl StringManagerUnicode {
    // Ghidra: stringmanage.cc:414 StringManagerUnicode::new
    /// Construct given a load image and maximum character count. Faithful to
    /// the constructor (stringmanage.cc:414).
    pub fn new(loader: Option<std::sync::Arc<dyn LoadImage>>, max: i32) -> Self {
        Self {
            manager: StringManager::new(max),
            loader,
        }
    }

    // Ghidra: stringmanage.cc:427 StringManagerUnicode::getStringData
    /// Retrieve string data at the given address, reading from the load image
    /// if not cached. Faithful to `StringManagerUnicode::getStringData`
    /// (stringmanage.cc:427).
    ///
    /// `charsize` is 1 for UTF8, 2 for UTF16, 4 for UTF32.
    /// Returns the decoded UTF8 byte data, or empty if not a valid string.
    pub fn get_string_data(
        &mut self,
        addr: Address,
        charsize: i32,
        bigend: bool,
    ) -> Vec<u8> {
        // Check cache.
        if let Some(data) = self.manager.get_string_data(addr) {
            return data.byte_data.clone();
        }
        let Some(loader) = &self.loader else {
            return Vec::new();
        };
        // Read a test buffer of bytes from the load image.
        let max_bytes = (self.manager.maximum_chars * charsize.max(1)) as usize;
        let buf = match loader.load_fill(max_bytes, addr) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        // Check if it's a valid string.
        let num_chars = check_characters(&buf, charsize, bigend);
        if num_chars < 0 {
            // Not a legal encoding; cache empty.
            self.manager.insert_string_data(addr, StringData::default());
            return Vec::new();
        }
        if !has_char_terminator(&buf, charsize as usize) {
            self.manager.insert_string_data(addr, StringData::default());
            return Vec::new();
        }
        let mut data = StringData::default();
        assign_string_data(
            &mut data,
            &buf,
            charsize,
            num_chars,
            bigend,
            self.manager.maximum_chars,
        );
        let result = data.byte_data.clone();
        self.manager.insert_string_data(addr, data);
        result
    }

    // Ghidra: stringmanage.cc:414 StringManagerUnicode::isString
    /// Check if the address contains a string, caching the result.
    pub fn is_string(&mut self, addr: Address, charsize: i32, bigend: bool) -> bool {
        let data = self.get_string_data(addr, charsize, bigend);
        !data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_utf8_ascii() {
        let mut out = Vec::new();
        write_utf8(&mut out, 65); // 'A'
        assert_eq!(out, vec![65]);
    }

    #[test]
    fn test_write_utf8_multibyte() {
        let mut out = Vec::new();
        // U+00E9 (é) = 2-byte UTF8: 0xC3 0xA9
        write_utf8(&mut out, 0xE9);
        assert_eq!(out, vec![0xC3, 0xA9]);
    }

    #[test]
    fn test_write_utf8_3byte() {
        let mut out = Vec::new();
        // U+4E2D (中) = 3-byte UTF8: 0xE4 0xB8 0xAD
        write_utf8(&mut out, 0x4E2D);
        assert_eq!(out, vec![0xE4, 0xB8, 0xAD]);
    }

    #[test]
    fn test_read_utf16_le() {
        // U+0041 ('A') in little-endian UTF16 = 0x41 0x00
        assert_eq!(read_utf16(&[0x41, 0x00], false), 0x41);
    }

    #[test]
    fn test_read_utf16_be() {
        // U+0041 ('A') in big-endian UTF16 = 0x00 0x41
        assert_eq!(read_utf16(&[0x00, 0x41], true), 0x41);
    }

    #[test]
    fn test_get_codepoint_utf8_ascii() {
        let (cp, skip) = get_codepoint(&[0x41], 1, false);
        assert_eq!(cp, 0x41);
        assert_eq!(skip, 1);
    }

    #[test]
    fn test_get_codepoint_utf8_multibyte() {
        // U+00E9 (é) encoded as 0xC3 0xA9
        let (cp, skip) = get_codepoint(&[0xC3, 0xA9], 1, false);
        assert_eq!(cp, 0xE9);
        assert_eq!(skip, 2);
    }

    #[test]
    fn test_get_codepoint_utf16_surrogate() {
        // U+10000 encoded as surrogate pair (big-endian): D800 DC00
        let (cp, skip) = get_codepoint(&[0xD8, 0x00, 0xDC, 0x00], 2, true);
        assert_eq!(cp, 0x10000);
        assert_eq!(skip, 4);
    }

    #[test]
    fn test_get_codepoint_invalid_trail() {
        // High surrogate (big-endian D800) without valid trail.
        let (cp, _) = get_codepoint(&[0xD8, 0x00, 0x00, 0x00], 2, true);
        assert_eq!(cp, -1);
    }

    #[test]
    fn test_check_characters_ascii() {
        // "Hello\0"
        let buf = [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00];
        assert_eq!(check_characters(&buf, 1, false), 5);
    }

    #[test]
    fn test_check_characters_invalid() {
        // Invalid UTF8: 0xFF
        let buf = [0xFF];
        assert_eq!(check_characters(&buf, 1, false), -1);
    }

    #[test]
    fn test_has_char_terminator_utf8() {
        assert!(has_char_terminator(&[0x41, 0x42, 0x00], 1));
        assert!(!has_char_terminator(&[0x41, 0x42, 0x43], 1));
    }

    #[test]
    fn test_has_char_terminator_utf16() {
        // 'A' + null terminator in UTF16-LE
        assert!(has_char_terminator(&[0x41, 0x00, 0x00, 0x00], 2));
        assert!(!has_char_terminator(&[0x41, 0x00, 0x42, 0x00], 2));
    }

    #[test]
    fn test_write_unicode_ascii() {
        let mut out = Vec::new();
        let buf = [0x48, 0x69, 0x00]; // "Hi\0"
        assert!(write_unicode(&mut out, &buf, 1, false, 100));
        assert_eq!(out, vec![0x48, 0x69]); // null terminator not emitted
    }

    #[test]
    fn test_string_manager_basic() {
        let mut sm = StringManager::new(100);
        assert_eq!(sm.num_strings(), 0);
        let mut data = StringData::default();
        data.byte_data = vec![b'H', b'i'];
        sm.insert_string_data(Address::new(0x1000), data);
        assert!(sm.is_string(Address::new(0x1000)));
        assert!(!sm.is_string(Address::new(0x2000)));
        assert_eq!(sm.num_strings(), 1);
        sm.clear();
        assert_eq!(sm.num_strings(), 0);
    }

    #[test]
    fn test_string_manager_unicode_no_loader() {
        let mut smu = StringManagerUnicode::new(None, 100);
        let result = smu.get_string_data(Address::new(0x1000), 1, false);
        assert!(result.is_empty());
    }

    #[test]
    fn test_assign_string_data_utf8() {
        let mut data = StringData::default();
        let buf = [b'H', b'e', b'l', b'l', b'o', 0x00];
        assign_string_data(&mut data, &buf, 1, 5, false, 100);
        assert_eq!(&data.byte_data[..5], b"Hello");
        assert!(!data.is_truncated);
    }

    #[test]
    fn test_assign_string_data_truncated() {
        let mut data = StringData::default();
        let buf = [b'A', b'B', b'C', 0x00];
        // maximum_chars = 2, so 3 chars >= 2 → truncated.
        assign_string_data(&mut data, &buf, 1, 3, false, 2);
        assert!(data.is_truncated);
        // UTF8 copy of first 2 chars + null terminator.
        assert_eq!(&data.byte_data, b"AB\0");
    }
}

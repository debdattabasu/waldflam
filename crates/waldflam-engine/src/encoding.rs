//! Order-preserving index-key encodings.
//!
//! Numbers use the ordered-number format documented in
//! docs/architecture.md §6/§11 (reimplemented from the behavioral spec, not
//! ported code): a number decomposes into sign / binary exponent / 64-bit
//! left-justified fraction-after-the-leading-1, then serializes into ≤11
//! prefix-free bytes whose unsigned lexicographic order equals numeric order
//! across the whole real line — int64 and double interleave exactly, and
//! equal values (`1` vs `1.0`) encode identically.
//!
//! Layout: NaN `00 60` < −∞ `00 80` < negatives < 0 `80` < positives < +∞
//! `FF`. Negative numbers are the bitwise complement of their magnitude's
//! encoding; negative exponents complement only the exponent bits. The
//! exponent self-delimits via four marker buckets (|e| < 4, < 20, < 148,
//! < 1172) and the significand streams 7 bits per byte, bit 0 as the
//! continuation flag, trailing zero groups elided.

/// A number in canonical sign/exponent/significand form:
/// `(-1)^negative × 1.significand × 2^exponent`, with the significand's
/// post-leading-1 fraction left-justified in 64 bits.
///
/// Sentinels: zero = `(false, i32::MIN, 0)`; ±∞ = `(neg, i32::MAX, 0)`;
/// NaN = `(true, i32::MAX, 1)` (payload and sign discarded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberParts {
    negative: bool,
    exponent: i32,
    significand: u64,
}

impl NumberParts {
    pub fn is_zero(&self) -> bool {
        self.exponent == i32::MIN && self.significand == 0
    }

    pub fn is_nan(&self) -> bool {
        self.exponent == i32::MAX && self.significand != 0
    }

    pub fn is_infinite(&self) -> bool {
        self.exponent == i32::MAX && self.significand == 0
    }

    const ZERO: Self = Self { negative: false, exponent: i32::MIN, significand: 0 };
    const NAN: Self = Self { negative: true, exponent: i32::MAX, significand: 1 };

    pub fn from_i64(value: i64) -> Self {
        if value == 0 {
            return Self::ZERO;
        }
        let negative = value < 0;
        let magnitude = value.unsigned_abs();
        let leading_zeros = magnitude.leading_zeros();
        let binary_exponent = (63 - leading_zeros) as i32;
        // Left-justify the bits below the leading 1. Shifting by
        // leading_zeros + 1 would discard the leading 1 itself, but that
        // shift is 64 when magnitude == 1, so clear the top bit first.
        let fraction = magnitude & !(1u64 << binary_exponent);
        let significand = if leading_zeros == 63 { 0 } else { fraction << (leading_zeros + 1) };
        Self { negative, exponent: binary_exponent, significand }
    }

    pub fn from_f64(value: f64) -> Self {
        let bits = value.to_bits();
        let negative = value < 0.0; // false for NaN and -0.0
        let biased = ((bits >> 52) & 0x7FF) as i32;
        let mantissa = bits & 0x000F_FFFF_FFFF_FFFF;
        if biased == 0 {
            // Subnormal (or zero): renormalize around the top set bit.
            if mantissa == 0 {
                return Self::ZERO; // covers -0.0 too
            }
            let leading_zeros = mantissa.leading_zeros();
            let binary_exponent = 63 - leading_zeros;
            let fraction = mantissa & !(1u64 << binary_exponent);
            Self {
                negative,
                // Normal doubles place the mantissa's implied 1 at bit 52
                // (leading_zeros == 11); each extra leading zero costs one
                // exponent step below the subnormal base of -1022.
                exponent: -1023 - (leading_zeros as i32 - 12),
                significand: if leading_zeros == 63 { 0 } else { fraction << (leading_zeros + 1) },
            }
        } else if biased == 0x7FF {
            if mantissa == 0 {
                Self { negative, exponent: i32::MAX, significand: 0 }
            } else {
                Self::NAN
            }
        } else {
            Self { negative, exponent: biased - 1023, significand: mantissa << 12 }
        }
    }

    /// Inverse of `from_f64` (lossy only for values that were never doubles).
    pub fn as_f64(&self) -> f64 {
        if self.is_zero() {
            return 0.0;
        }
        if self.is_infinite() {
            return if self.negative { f64::NEG_INFINITY } else { f64::INFINITY };
        }
        if self.is_nan() {
            return f64::NAN;
        }
        let (mantissa, biased) = if self.exponent >= -1022 {
            (self.significand >> 12, (self.exponent + 1023) as u64)
        } else {
            let adjustment = (-1022 - self.exponent) as u32;
            ((self.significand >> 12 >> adjustment) | (1u64 << (52 - adjustment)), 0)
        };
        let sign = if self.negative { 1u64 << 63 } else { 0 };
        f64::from_bits(sign | (biased << 52) | mantissa)
    }

    /// Inverse of `from_i64`; panics if the parts hold a non-integer.
    pub fn as_i64(&self) -> i64 {
        if self.is_zero() {
            return 0;
        }
        assert!(
            (0..=63).contains(&self.exponent),
            "not an i64: {self:?}"
        );
        if self.exponent == 63 {
            assert!(self.negative && self.significand == 0, "i64 overflow: {self:?}");
            return i64::MIN;
        }
        let trailing = self.significand.trailing_zeros();
        assert!(
            self.significand == 0 || self.exponent >= (64 - trailing) as i32,
            "fractional part: {self:?}"
        );
        let leading_zeros = 63 - self.exponent as u32;
        let fraction = if leading_zeros == 63 { 0 } else { self.significand >> (leading_zeros + 1) };
        let magnitude = fraction | (1u64 << self.exponent);
        let value = magnitude as i64;
        if self.negative { -value } else { value }
    }
}

/// Encodes into the order-preserving byte form (≤11 bytes).
pub fn encode_number(parts: NumberParts) -> Vec<u8> {
    if parts.is_zero() {
        return vec![0x80];
    }
    if parts.is_nan() {
        return vec![0x00, 0x60];
    }
    if parts.is_infinite() {
        return if parts.negative { vec![0x00, 0x80] } else { vec![0xFF] };
    }

    let inverter: u32 = if parts.negative { 0xFF } else { 0x00 };
    let (exponent, exponent_mask): (u32, u32) = if parts.exponent < 0 {
        ((-parts.exponent) as u32, 0xFF)
    } else {
        (parts.exponent as u32, 0x00)
    };

    let mut buf = [0u8; 11];
    let mut pos = 0usize;
    let mut significand = parts.significand;
    let mut last_byte: u32;

    if exponent < 4 {
        // Exponent lives in the position of a marker bit inside the first
        // byte; up to `exponent` significand bits ride along under it.
        let significand_start = exponent + 1;
        last_byte = 0xC0 | (1u32 << significand_start);
        let significand_mask = (1u32 << significand_start) - 2;
        last_byte |= ((significand >> (64 - significand_start)) as u32) & significand_mask;
        significand <<= exponent;
        if exponent_mask != 0 {
            let exponent_inverter = ((!0u32) << significand_start) & 126;
            last_byte ^= exponent_inverter;
        }
    } else if exponent < 20 {
        buf[pos] = ((0xE0 | (exponent - 4)) ^ ((0x7F & exponent_mask) ^ inverter)) as u8;
        pos += 1;
        last_byte = top_significand_byte(significand);
        significand <<= 7;
    } else if exponent < 148 {
        let e = exponent - 20;
        buf[pos] = ((0xF0 | (e >> 4)) ^ ((0x7F & exponent_mask) ^ inverter)) as u8;
        pos += 1;
        let second = ((e << 4) & 0xF0) | (significand >> 60) as u32;
        buf[pos] = (second ^ ((0xF0 & exponent_mask) ^ inverter)) as u8;
        pos += 1;
        significand <<= 4;
        last_byte = top_significand_byte(significand);
        significand <<= 7;
    } else if exponent < 1172 {
        let e = exponent - 148;
        buf[pos] = ((0xF8 | (e >> 8)) ^ ((0x7F & exponent_mask) ^ inverter)) as u8;
        pos += 1;
        buf[pos] = ((e & 0xFF) ^ ((0xFF & exponent_mask) ^ inverter)) as u8;
        pos += 1;
        last_byte = top_significand_byte(significand);
        significand <<= 7;
    } else {
        unreachable!("exponent {exponent} out of encodable range");
    }

    // Stream the remaining significand 7 bits per byte; bit 0 marks
    // continuation. Trailing zero groups are elided (prefix-free).
    while significand != 0 {
        buf[pos] = (((last_byte | 1) ^ inverter) & 0xFF) as u8;
        pos += 1;
        last_byte = top_significand_byte(significand);
        significand <<= 7;
    }
    buf[pos] = ((last_byte ^ inverter) & 0xFF) as u8;
    buf[..pos + 1].to_vec()
}

pub fn encode_i64(value: i64) -> Vec<u8> {
    encode_number(NumberParts::from_i64(value))
}

pub fn encode_f64(value: f64) -> Vec<u8> {
    encode_number(NumberParts::from_f64(value))
}

#[derive(Debug, PartialEq, Eq)]
pub struct DecodeError(&'static str);

/// Decodes one number from the front of `bytes`; returns the parts and the
/// number of bytes consumed (the encoding is self-delimiting).
pub fn decode_number(bytes: &[u8]) -> Result<(NumberParts, usize), DecodeError> {
    let err = |m| Err(DecodeError(m));
    let Some(&b0) = bytes.first() else {
        return err("empty input");
    };
    let b0 = b0 as u32;
    let negative = b0 & 0x80 == 0;
    let inverter: u32 = if negative { 0xFF } else { 0x00 };
    let b0 = b0 ^ inverter;
    let exponent_negative = b0 & 0x40 == 0;
    let exponent_inverter: u32 = if exponent_negative { 0xFF } else { 0x00 };

    let marker = decode_marker((b0 ^ exponent_inverter) & 0xFF);
    let mut pos = 1usize;
    let mut significand: u64 = 0;
    let mut write_bit: i32 = 64;
    let mut current: u32 = b0;
    let exponent_magnitude: u32;

    match marker {
        -4 => {
            if exponent_negative {
                return err("negative zero exponent is invalid");
            }
            exponent_magnitude = 0;
        }
        -3 | -2 | -1 => {
            let exp = (4 + marker) as u32; // 1..=3
            exponent_magnitude = exp;
            write_bit = 64 - exp as i32;
            let significand_start = exp + 1;
            let significand_mask = (!((!0u32) << significand_start)) & 126;
            significand |= ((current & significand_mask) as u64) << (write_bit - 1);
        }
        1 => {
            let Some(&b1) = bytes.get(1) else {
                return err("truncated input");
            };
            exponent_magnitude = ((current ^ exponent_inverter) & 0x0F) + 4;
            current = (b1 as u32) ^ inverter;
            pos = 2;
            write_bit = 64 - 7;
            significand |= decode_trailing_byte(current, write_bit);
        }
        2 => {
            let (Some(&b1), Some(&b2)) = (bytes.get(1), bytes.get(2)) else {
                return err("truncated input");
            };
            let high = ((current ^ exponent_inverter) & 0x07) << 4;
            let b1 = (b1 as u32) ^ inverter;
            exponent_magnitude = (high | ((b1 ^ exponent_inverter) >> 4)) + 20;
            write_bit = 64 - 4;
            significand |= ((b1 & 0x0F) as u64) << write_bit;
            current = (b2 as u32) ^ inverter;
            pos = 3;
            write_bit -= 7;
            significand |= decode_trailing_byte(current, write_bit);
        }
        3 => {
            let (Some(&b1), Some(&b2)) = (bytes.get(1), bytes.get(2)) else {
                return err("truncated input");
            };
            let high = ((current ^ exponent_inverter) & 0x03) << 8;
            exponent_magnitude = (high | (((b1 as u32) ^ inverter) ^ exponent_inverter)) + 148;
            current = (b2 as u32) ^ inverter;
            pos = 3;
            write_bit = 64 - 7;
            significand |= decode_trailing_byte(current, write_bit);
        }
        6 => {
            // Sentinels: zero, ±infinity, NaN.
            let parts = match (negative, exponent_negative) {
                (false, true) | (true, true) => NumberParts::ZERO,
                (false, false) => NumberParts { negative: false, exponent: i32::MAX, significand: 0 },
                (true, false) => match bytes.get(1) {
                    Some(0x80) => NumberParts { negative: true, exponent: i32::MAX, significand: 0 },
                    Some(0x60) => NumberParts::NAN,
                    _ => return err("invalid sentinel"),
                },
            };
            let consumed = if (negative, exponent_negative) == (true, false) { 2 } else { 1 };
            return Ok((parts, consumed));
        }
        _ => return err("invalid marker byte"),
    }

    while current & 1 != 0 {
        let Some(&b) = bytes.get(pos) else {
            return err("truncated continuation");
        };
        pos += 1;
        current = (b as u32) ^ inverter;
        write_bit -= 7;
        if write_bit >= 0 {
            significand |= decode_trailing_byte(current, write_bit);
        } else {
            significand |= ((current & 0xFE) as u64) >> (1 - write_bit);
            write_bit = 0;
            if current & 1 != 0 {
                return err("overlong sequence");
            }
        }
    }

    let exponent = if exponent_negative {
        -(exponent_magnitude as i32)
    } else {
        exponent_magnitude as i32
    };
    Ok((NumberParts { negative, exponent, significand }, pos))
}

fn decode_marker(byte: u32) -> i32 {
    let leading_one = byte & 0x20 != 0;
    let value = if leading_one { byte ^ 0xFF } else { byte } & 0x3F;
    let log2 = 31 - (value.leading_zeros() as i32); // -1 when value == 0
    let leader = 5 - log2;
    if leading_one { leader } else { -leader }
}

fn decode_trailing_byte(value: u32, position: i32) -> u64 {
    ((value & 0xFE) as u64) << (position - 1)
}

fn top_significand_byte(significand: u64) -> u32 {
    ((significand >> 56) & 0xFE) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    use waldflam_proto::v1::Value;
    use waldflam_proto::v1::value::ValueType;

    use crate::order::compare_values;

    #[test]
    fn sentinel_vectors() {
        assert_eq!(encode_i64(0), vec![0x80]);
        assert_eq!(encode_f64(0.0), vec![0x80]);
        assert_eq!(encode_f64(-0.0), vec![0x80]);
        assert_eq!(encode_f64(f64::NAN), vec![0x00, 0x60]);
        assert_eq!(encode_f64(f64::NEG_INFINITY), vec![0x00, 0x80]);
        assert_eq!(encode_f64(f64::INFINITY), vec![0xFF]);
    }

    #[test]
    fn equal_int_and_double_encode_identically() {
        for v in [0i64, 1, -1, 2, 42, 1 << 20, -(1 << 20), 1 << 52, -(1 << 52)] {
            assert_eq!(encode_i64(v), encode_f64(v as f64), "{v}");
        }
    }

    fn i64_corpus() -> Vec<i64> {
        let mut c = vec![0i64, 1, -1, 2, -2, 3, -3, 7, 10, 100, 127, 128, -127, -128];
        for shift in [8, 16, 20, 31, 32, 33, 51, 52, 53, 62] {
            for delta in [-1i64, 0, 1] {
                c.push((1i64 << shift) + delta);
                c.push(-(1i64 << shift) + delta);
            }
        }
        c.extend([i64::MAX, i64::MIN, i64::MAX - 1, i64::MIN + 1]);
        c
    }

    fn f64_corpus() -> Vec<f64> {
        let mut c = vec![
            0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 0.25, 1.5, -1.5, 2.5, 3.75,
            f64::NAN, f64::INFINITY, f64::NEG_INFINITY,
            f64::MIN_POSITIVE,                 // smallest normal
            f64::MIN_POSITIVE / 4.0,           // subnormal
            5e-324,                            // smallest subnormal
            -5e-324,
            f64::MAX, f64::MIN,
            1e-300, -1e-300, 1e300, -1e300,
            (1u64 << 53) as f64, ((1u64 << 53) + 2) as f64,
            9.3e18, -9.3e18,                   // beyond i64 range
            0.1, -0.1, 3.141592653589793,
        ];
        // Exercise every exponent bucket boundary: |e| in {3,4,19,20,147,148}.
        for e in [3i32, 4, 19, 20, 147, 148, -3, -4, -19, -20, -147, -148] {
            c.push((2.0f64).powi(e));
            c.push(-(2.0f64).powi(e));
            c.push((2.0f64).powi(e) * 1.5);
        }
        c
    }

    #[test]
    fn round_trips() {
        for v in i64_corpus() {
            let enc = encode_i64(v);
            assert!(enc.len() <= 11, "{v}: {} bytes", enc.len());
            let (parts, read) = decode_number(&enc).unwrap();
            assert_eq!(read, enc.len(), "{v}");
            assert_eq!(parts.as_i64(), v);
        }
        for v in f64_corpus() {
            let enc = encode_f64(v);
            assert!(enc.len() <= 11, "{v}: {} bytes", enc.len());
            let (parts, read) = decode_number(&enc).unwrap();
            assert_eq!(read, enc.len(), "{v}");
            let back = parts.as_f64();
            assert!(back == v || (back.is_nan() && v.is_nan()), "{v} -> {back}");
        }
    }

    #[test]
    fn self_delimiting_with_trailing_data() {
        for v in [0i64, 1, -1, 1 << 40, i64::MIN] {
            let mut enc = encode_i64(v);
            let len = enc.len();
            enc.extend_from_slice(&[0xAB, 0xCD]);
            let (parts, read) = decode_number(&enc).unwrap();
            assert_eq!(read, len);
            assert_eq!(parts.as_i64(), v);
        }
    }

    /// Byte order must equal the semantic order from `order::compare_values`
    /// across the full mixed int/double corpus.
    #[test]
    fn byte_order_matches_value_order() {
        #[derive(Clone, Copy, Debug)]
        enum Num {
            I(i64),
            D(f64),
        }
        let to_value = |n: Num| Value {
            value_type: Some(match n {
                Num::I(i) => ValueType::IntegerValue(i),
                Num::D(d) => ValueType::DoubleValue(d),
            }),
        };
        let encode = |n: Num| match n {
            Num::I(i) => encode_i64(i),
            Num::D(d) => encode_f64(d),
        };

        let corpus: Vec<Num> = i64_corpus()
            .into_iter()
            .map(Num::I)
            .chain(f64_corpus().into_iter().map(Num::D))
            .collect();

        for &a in &corpus {
            for &b in &corpus {
                let semantic = compare_values(&to_value(a), &to_value(b));
                let bytes = encode(a).cmp(&encode(b));
                assert_eq!(semantic, bytes, "{a:?} vs {b:?}");
                if semantic == Ordering::Equal {
                    assert_eq!(encode(a), encode(b), "{a:?} vs {b:?}");
                }
            }
        }
    }
}

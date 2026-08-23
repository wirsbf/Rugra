// FLOAT-OPINT2FLOAT-SIGN-0001 fixture — FloatFormat::opInt2Float signedness
// and opFloat2Float's bit-level convertEncoding against locked Ghidra 12.0.4.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Lease background: RULE-COLLAPSECONSTANTS-0001 could only cover
// FLOAT_INT2FLOAT with a positive input (7) because Rugra's op_int2float
// treated the integer as unsigned; this fixture proves the signed reading on
// both sides with same-input/same-output bit patterns.
//
// Drives the two public entry points directly (no Architecture/Translate —
// FloatFormat's public constructor builds the same IEEE 754 single/double
// defaults that Translate::getFloatFormat serves, translate.cc:966-971):
//
//   opInt2Float(a, sizein)      (float.cc:611-617)
//     intb ival = sign_extend(a, 8*sizein-1);  // address.hh:543-549
//     double val = (double) ival;              // round-to-nearest-even cast
//     return getEncoding(val);
//   Covered: negatives at every input width (1/2/4/8 bytes), 4- and 8-byte
//   float targets, sign_extend's discard of bits above the sizein sign bit,
//   INT32_MIN/INT32_MAX and i64::MIN/MIN+1/MAX boundary cast rounding
//   (the (double) cast is the oracle's "overflow" semantics — RNE, never a
//   trap), zero, and -1.
//
//   opFloat2Float(a, outformat) (float.cc:622-626)
//     return outformat.convertEncoding(a, this);  // float.cc:352-419
//   Covered: widening 4->8 and narrowing 8->4 with negative values, negative
//   zero, negative NaN (sign preserved through getNaNEncoding), infinity,
//   subnormal inputs (normalize branch via count_leading_zeros,
//   address.cc:773), exact round-to-nearest-even ties and one-ULP-above-tie
//   narrowing (roundToNearestEven float.cc:276-288 incl. the uintb wrap
//   carry on DBL_MAX), denormalized output (2^-127 -> subnormal float),
//   underflow to zero, and overflow to infinity.
//
// Observation: one line per case, `case=<name>|res=0x<16 uppercase hex>`
// (res is the full uintb result; the format's own size masks nothing here —
// callers like PcodeOp::collapse mask to the output varnode size).
#include <cstdio>

#include "float.hh"

using namespace ghidra;

namespace {

void i2f(const char *name, const FloatFormat &fmt, uintb a, int4 sizein)
{
  std::printf("case=%s|res=0x%016llX\n", name,
              static_cast<unsigned long long>(fmt.opInt2Float(a, sizein)));
}

void f2f(const char *name, const FloatFormat &formin, uintb a,
         const FloatFormat &outformat)
{
  std::printf("case=%s|res=0x%016llX\n", name,
              static_cast<unsigned long long>(formin.opFloat2Float(a, outformat)));
}

} // namespace

int main()
{
  std::printf("schema=1|fixture=FLOAT-OPINT2FLOAT-SIGN-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n");
  const FloatFormat fmt4(4);
  const FloatFormat fmt8(8);

  // ---- FLOAT_INT2FLOAT: signed reading, widths, boundaries ----
  // positive regression anchors (agree with the old unsigned reading)
  i2f("i2f4_pos7", fmt4, 0x00000007, 4);          // 7 -> 7.0f
  i2f("i2f8_pos7", fmt8, 0x00000007, 4);          // 7 -> 7.0d
  i2f("i2f4_zero", fmt4, 0x00000000, 4);          // 0 -> +0.0f
  // negatives at every input width, both target sizes
  i2f("i2f4_neg7", fmt4, 0xFFFFFFF9, 4);          // -7 -> -7.0f
  i2f("i2f8_neg7", fmt8, 0xFFFFFFF9, 4);          // -7 -> -7.0d
  i2f("i2f4_neg7_size1", fmt4, 0xF9, 1);          // -7 (1 byte) -> -7.0f
  i2f("i2f4_neg9_size2", fmt4, 0xFFF7, 2);        // -9 (2 bytes) -> -9.0f
  i2f("i2f4_neg7_size8", fmt4, 0xFFFFFFFFFFFFFFF9ULL, 8); // -7 (8 bytes) -> -7.0f
  i2f("i2f8_neg1", fmt8, 0xFFFFFFFF, 4);          // -1 -> -1.0d
  // sign_extend discards bits above the sizein sign bit
  i2f("i2f8_neg7_junk", fmt8, 0xABCDFFFFFFF9ULL, 4); // junk high 32 bits dropped
  // 32-bit boundaries: exact min, RNE max (2147483647 -> 2^31), 2^24+1 -> 2^24
  i2f("i2f4_int32_min", fmt4, 0x80000000, 4);
  i2f("i2f4_int32_max", fmt4, 0x7FFFFFFF, 4);
  i2f("i2f4_2p24p1", fmt4, 0x01000001, 4);
  // 64-bit boundaries: i64::MIN exact; MIN+1 and MAX round to -+2^63 (RNE)
  i2f("i2f8_int64_min", fmt8, 0x8000000000000000ULL, 8);
  i2f("i2f8_int64_min1", fmt8, 0x8000000000000001ULL, 8);
  i2f("i2f8_int64_max", fmt8, 0x7FFFFFFFFFFFFFFFULL, 8);

  // ---- FLOAT_FLOAT2FLOAT: convertEncoding ladder ----
  // widening 4 -> 8
  f2f("f2f_4to8_onefive", fmt4, 0x3FC00000, fmt8);   // 1.5f -> 1.5d
  f2f("f2f_4to8_neg1", fmt4, 0xBF800000, fmt8);      // -1.0f -> -1.0d
  f2f("f2f_4to8_negzero", fmt4, 0x80000000, fmt8);   // -0.0f -> -0.0d
  f2f("f2f_4to8_nan", fmt4, 0x7FC00000, fmt8);       // NaN sign preserved
  f2f("f2f_4to8_negnan", fmt4, 0xFFC00000, fmt8);    // -NaN -> -NaNd
  f2f("f2f_4to8_posinf", fmt4, 0x7F800000, fmt8);    // +inf -> +infd
  f2f("f2f_4to8_sub_min", fmt4, 0x00000001, fmt8);   // 2^-149 subnormal normalize
  f2f("f2f_4to8_sub_max", fmt4, 0x007FFFFF, fmt8);   // max subnormal
  // narrowing 8 -> 4
  f2f("f2f_8to4_neg1", fmt8, 0xBFF0000000000000ULL, fmt4);   // -1.0d -> -1.0f
  f2f("f2f_8to4_negthird", fmt8, 0xBFD5555555555555ULL, fmt4); // -(1/3) RNE
  f2f("f2f_8to4_tie_even", fmt8, 0x3FF0000010000000ULL, fmt4); // 1+2^-24 tie -> even
  f2f("f2f_8to4_above_tie", fmt8, 0x3FF0000018000000ULL, fmt4); // above tie -> up
  f2f("f2f_8to4_negtie", fmt8, 0xBFF0000010000000ULL, fmt4);   // -tie -> -even
  f2f("f2f_8to4_sub_out", fmt8, 0x3800000000000000ULL, fmt4);  // 2^-127 -> subnormal
  f2f("f2f_8to4_too_small", fmt8, 0x2100000000000000ULL, fmt4); // underflow -> zero
  f2f("f2f_8to4_dbl_max", fmt8, 0x7FEFFFFFFFFFFFFFULL, fmt4);  // wrap carry -> inf
  f2f("f2f_8to4_negdbl_max", fmt8, 0xFFEFFFFFFFFFFFFFULL, fmt4); // -inf
  f2f("f2f_8to4_negnan", fmt8, 0xFFF8000000000000ULL, fmt4);   // -NaN
  f2f("f2f_8to4_neginf", fmt8, 0xFFF0000000000000ULL, fmt4);   // -inf
  f2f("f2f_8to4_negzero", fmt8, 0x8000000000000000ULL, fmt4);  // -0.0
  return 0;
}

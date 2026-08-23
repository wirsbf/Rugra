// FLOAT-FMT-STRUCT-0001 fixture — FloatFormat structural 1:1 against locked
// Ghidra 12.0.4: the 64-bit top-aligned fractional-code convention and the
// createFloat/extractExpSig bit ladders behind getHostFloat/getEncoding.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Lease background: FLOAT-OPINT2FLOAT-SIGN-0001 delivered value equivalence
// (36/36 MATCH) but left a structural residual — Rugra's host conversions
// used host f32/f64 bit-casts / powi products while the oracle runs
// createFloat/extractExpSig (float.cc:67-108) bit ladders with the
// **64-bit top-aligned** fractional code convention
// (extractFractionalCode/setFractionalCode, float.cc:113-153). This fixture
// observes the internal bit representations directly on both sides:
//
//   - FloatFormat field initialization incl. jbitimplied (float.cc:36-61)
//   - top-aligned extractors extractFractionalCode/extractSign/
//     extractExponentCode (float.cc:113-139; public surface)
//   - OR-style setters setFractionalCode/setSign/setExponentCode
//     (float.cc:144-177; setSign(false) is an identity, no masking of x)
//   - getZeroEncoding/getInfinityEncoding/getNaNEncoding 3-setter structure
//     (float.cc:181-215; the quiet-NaN mask is created top-aligned 1<<63)
//   - static createFloat incl. ldexp gradual-underflow/overflow saturation
//     (float.cc:67-80) — 2^-1074 exact, 2^-1075 ties-to-even flush, 1.5x tie
//   - static extractExpSig (float.cc:89-109) with sentinel out-params that
//     prove the zero/inf/NaN early returns never write signif/exp
//   - static roundToNearestEven (float.cc:276-288) incl. the uintb
//     wrap-around carry and the lowbitpos==64 zero lowbitmask
//   - the subnormal-normalize intermediate state of convertEncoding
//     (float.cc:368-376): count_leading_zeros (address.cc:773) of the
//     top-aligned signif, the <<lz normalized signif, exp = -bias - lz
//   - getHostFloat across all five floatclasses incl. the denormalized
//     createFloat path (float.cc:228-268)
//   - getEncoding ladder incl. RNE ties, denormalized outputs, and NaN
//     payload canonicalization through getNaNEncoding (float.cc:293-346)
//   - the full FLOAT-OPINT2FLOAT-SIGN-0001 36-case value regression
//     (structural refactor must not change value behavior)
//
// The private statics/members are reached with the private->public access
// hack the address_space_phase1/block_index_assign fixtures established
// (std headers pulled first via <bits/stdc++.h>; the rewrite only touches
// Ghidra declarations in this translation unit). The Rust comparand drives
// the pub FloatFormat API (float_emulate.rs) with identical inputs and must
// match byte for byte.
#include <bits/stdc++.h>

#define private public
#include "address.hh"
#include "float.hh"
#undef private

using namespace ghidra;

namespace {

std::uint64_t dbits(double d)
{
  std::uint64_t u;
  std::memcpy(&u, &d, sizeof u);
  return u;
}

double frombits(std::uint64_t u)
{
  double d;
  std::memcpy(&d, &u, sizeof d);
  return d;
}

void fields(const char *name, const FloatFormat &fmt)
{
  std::printf("case=%s|size=%d|signbit_pos=%d|exp_pos=%d|exp_size=%d|"
              "frac_pos=%d|frac_size=%d|bias=%d|maxexp=%d|jbitimplied=%d\n",
              name, fmt.size, fmt.signbit_pos, fmt.exp_pos, fmt.exp_size,
              fmt.frac_pos, fmt.frac_size, fmt.bias, fmt.maxexponent,
              (int)fmt.jbitimplied);
}

void esig(const char *name, double x)
{
  // Sentinels prove the zero/infinity/NaN early returns leave the out
  // params untouched (float.cc:95-97 return before any write).
  bool sgn = false;
  uintb signif = 0xAAAAAAAAAAAAAAAAULL;
  int4 exp = -559038737;
  FloatFormat::floatclass cls = FloatFormat::extractExpSig(x, &sgn, &signif, &exp);
  std::printf("case=%s|cls=%d|sgn=%d|signif=0x%016llX|exp=%d\n", name,
              (int)cls, (int)sgn, (unsigned long long)signif, exp);
}

void rtne(const char *name, uintb signif, int4 lowbitpos)
{
  bool up = FloatFormat::roundToNearestEven(signif, lowbitpos);
  std::printf("case=%s|up=%d|signif=0x%016llX\n", name, (int)up,
              (unsigned long long)signif);
}

void ghf(const char *name, const FloatFormat &fmt, uintb encoding)
{
  FloatFormat::floatclass type = FloatFormat::normalized;
  double val = fmt.getHostFloat(encoding, &type);
  std::printf("case=%s|cls=%d|val=0x%016llX\n", name, (int)type,
              (unsigned long long)dbits(val));
}

void genc(const char *name, const FloatFormat &fmt, double host)
{
  std::printf("case=%s|res=0x%016llX\n", name,
              (unsigned long long)fmt.getEncoding(host));
}

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
  std::printf("schema=1|fixture=FLOAT-FMT-STRUCT-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n");
  const FloatFormat fmt4(4);
  const FloatFormat fmt8(8);

  // ---- FloatFormat field initialization (float.cc:36-61) ----
  fields("fields4", fmt4);
  fields("fields8", fmt8);

  // ---- top-aligned field extraction (float.cc:113-139) ----
  // frac MSB lands in bit 63 (right-aligned reads would differ).
  std::printf("case=xfrac4_minfrac|res=0x%016llX\n",
              (unsigned long long)fmt4.extractFractionalCode(0x00800001));
  std::printf("case=xfrac4_maxfrac|res=0x%016llX\n",
              (unsigned long long)fmt4.extractFractionalCode(0x007FFFFF));
  std::printf("case=xfrac4_3fc00001|res=0x%016llX\n",
              (unsigned long long)fmt4.extractFractionalCode(0x3FC00001));
  std::printf("case=xfrac8_one_ulp|res=0x%016llX\n",
              (unsigned long long)fmt8.extractFractionalCode(0x3FF0000000000001ULL));
  std::printf("case=xfrac8_maxsub|res=0x%016llX\n",
              (unsigned long long)fmt8.extractFractionalCode(0x000FFFFFFFFFFFFFULL));
  std::printf("case=xsign4_pos|res=%d\n", (int)fmt4.extractSign(0x3FC00000));
  std::printf("case=xsign4_neg|res=%d\n", (int)fmt4.extractSign(0xFF800000));
  std::printf("case=xsign8_neg|res=%d\n", (int)fmt8.extractSign(0xFFF0000000000000ULL));
  std::printf("case=xexp4_onefive|res=%d\n", fmt4.extractExponentCode(0x3FC00000));
  std::printf("case=xexp4_inf|res=%d\n", fmt4.extractExponentCode(0x7F800000));
  std::printf("case=xexp4_sub|res=%d\n", fmt4.extractExponentCode(0x00000001));
  std::printf("case=xexp8_max|res=%d\n", fmt8.extractExponentCode(0x7FEFFFFFFFFFFFFFULL));

  // ---- OR-style setters (float.cc:144-177) ----
  // code arrives top-aligned; setSign(false) never clears; no masking of x.
  std::printf("case=sfrac4_into_zero|res=0x%016llX\n",
              (unsigned long long)fmt4.setFractionalCode(0, 0xC000000000000000ULL));
  std::printf("case=sfrac4_or_dirty|res=0x%016llX\n",
              (unsigned long long)fmt4.setFractionalCode(0x3F800000, 0xC000000000000000ULL));
  std::printf("case=sfrac8_into_zero|res=0x%016llX\n",
              (unsigned long long)fmt8.setFractionalCode(0, 0x8000000000000000ULL));
  std::printf("case=sfrac8_or_dirty|res=0x%016llX\n",
              (unsigned long long)fmt8.setFractionalCode(0x3FF0000000000000ULL, 0x8000000000000000ULL));
  std::printf("case=ssign4_set|res=0x%016llX\n",
              (unsigned long long)fmt4.setSign(0x7F800000, true));
  std::printf("case=ssign4_identity|res=0x%016llX\n",
              (unsigned long long)fmt4.setSign(0xFF800000, false));
  std::printf("case=sexp4_or|res=0x%016llX\n",
              (unsigned long long)fmt4.setExponentCode(0x007FFFFF, 1));
  std::printf("case=sexp4_into_zero|res=0x%016llX\n",
              (unsigned long long)fmt4.setExponentCode(0, 129));

  // ---- zero/infinity/nan encodings (float.cc:181-215) ----
  std::printf("case=z4_pos|res=0x%016llX\n", (unsigned long long)fmt4.getZeroEncoding(false));
  std::printf("case=z4_neg|res=0x%016llX\n", (unsigned long long)fmt4.getZeroEncoding(true));
  std::printf("case=inf4_pos|res=0x%016llX\n", (unsigned long long)fmt4.getInfinityEncoding(false));
  std::printf("case=inf4_neg|res=0x%016llX\n", (unsigned long long)fmt4.getInfinityEncoding(true));
  std::printf("case=nan4_pos|res=0x%016llX\n", (unsigned long long)fmt4.getNaNEncoding(false));
  std::printf("case=nan4_neg|res=0x%016llX\n", (unsigned long long)fmt4.getNaNEncoding(true));
  std::printf("case=z8_pos|res=0x%016llX\n", (unsigned long long)fmt8.getZeroEncoding(false));
  std::printf("case=z8_neg|res=0x%016llX\n", (unsigned long long)fmt8.getZeroEncoding(true));
  std::printf("case=inf8_pos|res=0x%016llX\n", (unsigned long long)fmt8.getInfinityEncoding(false));
  std::printf("case=inf8_neg|res=0x%016llX\n", (unsigned long long)fmt8.getInfinityEncoding(true));
  std::printf("case=nan8_pos|res=0x%016llX\n", (unsigned long long)fmt8.getNaNEncoding(false));
  std::printf("case=nan8_neg|res=0x%016llX\n", (unsigned long long)fmt8.getNaNEncoding(true));

  // ---- static createFloat ldexp ladder (float.cc:67-80) ----
  std::printf("case=cf_pos7|res=0x%016llX\n",
              (unsigned long long)dbits(FloatFormat::createFloat(false, 0xE000000000000000ULL, 2)));
  std::printf("case=cf_neg7|res=0x%016llX\n",
              (unsigned long long)dbits(FloatFormat::createFloat(true, 0xE000000000000000ULL, 2)));
  std::printf("case=cf_onefive|res=0x%016llX\n",
              (unsigned long long)dbits(FloatFormat::createFloat(false, 0xC000000000000000ULL, 0)));
  // gradual underflow: 2^62 * 2^-1136 == 2^-1074 exactly (powi flushes)
  std::printf("case=cf_min_denorm|res=0x%016llX\n",
              (unsigned long long)dbits(FloatFormat::createFloat(false, 0x8000000000000000ULL, -1074)));
  // 2^-1075 is the exact half of the min denormal -> ties-to-even +0
  std::printf("case=cf_half_below|res=0x%016llX\n",
              (unsigned long long)dbits(FloatFormat::createFloat(false, 0x8000000000000000ULL, -1075)));
  // 1.5x tie between 1x (odd mantissa) and 2x (even) -> keeps 2x
  std::printf("case=cf_tie_even|res=0x%016llX\n",
              (unsigned long long)dbits(FloatFormat::createFloat(false, 0xC000000000000000ULL, -1074)));
  std::printf("case=cf_overflow|res=0x%016llX\n",
              (unsigned long long)dbits(FloatFormat::createFloat(false, 0x8000000000000000ULL, 1024)));
  std::printf("case=cf_neg_overflow|res=0x%016llX\n",
              (unsigned long long)dbits(FloatFormat::createFloat(true, 0x8000000000000000ULL, 1024)));

  // ---- static extractExpSig frexp/ldexp ladder (float.cc:89-109) ----
  esig("esig_7", 7.0);
  esig("esig_neg7", -7.0);
  esig("esig_half", 0.5);
  esig("esig_onefive", 1.5);
  esig("esig_min_denorm", frombits(0x0000000000000001ULL));
  esig("esig_max_normal", frombits(0x7FEFFFFFFFFFFFFFULL));
  esig("esig_zero", 0.0);
  esig("esig_negzero", frombits(0x8000000000000000ULL));
  esig("esig_inf", std::numeric_limits<double>::infinity());
  esig("esig_neginf", -std::numeric_limits<double>::infinity());
  esig("esig_nan", std::numeric_limits<double>::quiet_NaN());
  esig("esig_negnan", frombits(0xFFF8000000000000ULL));

  // ---- static roundToNearestEven (float.cc:276-288) ----
  rtne("rtne_even_stay", 0b1010, 2);            // even, exact tie -> stays
  rtne("rtne_odd_carry", 0b1110, 2);            // odd, exact tie -> carries
  rtne("rtne_eps_carry", 0b1011, 2);            // eps bits set -> carries
  rtne("rtne_wrap", ~((uintb)0), 2);            // uintb wrap-around carry
  rtne("rtne_lowbit64_wrap", 0x8000000000000003ULL, 64); // lowbitmask 0, wrap
  rtne("rtne_lowbit64_stay", 0x8000000000000000ULL, 64); // exact tie, even

  // ---- convertEncoding subnormal-normalize intermediate (float.cc:368-376,
  //      count_leading_zeros at address.cc:773) ----
  {
    uintb signif = fmt4.extractFractionalCode(0x00000001);
    int4 lz = count_leading_zeros(signif);
    std::printf("case=lz4_min|lz=%d|normsignif=0x%016llX|exp=%d\n", lz,
                (unsigned long long)(signif << lz), -fmt4.bias - lz);
  }
  {
    uintb signif = fmt4.extractFractionalCode(0x00000002);
    int4 lz = count_leading_zeros(signif);
    std::printf("case=lz4_two|lz=%d|normsignif=0x%016llX|exp=%d\n", lz,
                (unsigned long long)(signif << lz), -fmt4.bias - lz);
  }
  {
    uintb signif = fmt4.extractFractionalCode(0x007FFFFF);
    int4 lz = count_leading_zeros(signif);
    std::printf("case=lz4_max|lz=%d|normsignif=0x%016llX|exp=%d\n", lz,
                (unsigned long long)(signif << lz), -fmt4.bias - lz);
  }
  std::printf("case=lz4_zero|lz=%d\n", count_leading_zeros(0));

  // ---- getHostFloat bit ladder (float.cc:228-268) ----
  ghf("gh4_onefive", fmt4, 0x3FC00000);   // normalized 1.5f
  ghf("gh4_neg7", fmt4, 0xC0E00000);      // normalized -7.0f
  ghf("gh4_denorm_min", fmt4, 0x00000001); // 2^-149 via createFloat
  ghf("gh4_denorm_max", fmt4, 0x007FFFFF);
  ghf("gh4_zero_pos", fmt4, 0x00000000);
  ghf("gh4_zero_neg", fmt4, 0x80000000);
  ghf("gh4_inf_pos", fmt4, 0x7F800000);
  ghf("gh4_inf_neg", fmt4, 0xFF800000);
  ghf("gh4_nan_pos", fmt4, 0x7FC00000);
  ghf("gh4_nan_neg", fmt4, 0xFFC00000);
  ghf("gh8_one", fmt8, 0x3FF0000000000000ULL);
  ghf("gh8_denorm_min", fmt8, 0x0000000000000001ULL); // ldexp(2^11,-1085)
  ghf("gh8_denorm_max", fmt8, 0x000FFFFFFFFFFFFFULL);
  ghf("gh8_zero_neg", fmt8, 0x8000000000000000ULL);
  ghf("gh8_nan_neg", fmt8, 0xFFF8000000000000ULL);

  // ---- getEncoding bit ladder (float.cc:293-346) ----
  genc("ge4_pos7", fmt4, 7.0);
  genc("ge4_neg7", fmt4, -7.0);
  genc("ge4_tie_even", fmt4, frombits(0x3FF0000010000000ULL)); // 1+2^-24 tie
  genc("ge4_above_tie", fmt4, frombits(0x3FF0000018000000ULL));
  genc("ge4_min_denorm", fmt4, ldexp(1.0, -149));
  genc("ge4_half_denorm", fmt4, ldexp(1.0, -150)); // half-tie -> even 0
  genc("ge4_tie_denorm", fmt4, 1.5 * ldexp(1.0, -149)); // tie -> even 2x
  genc("ge4_exp_zero", fmt4, ldexp(1.0, -127)); // exp==0 boundary
  genc("ge4_too_small", fmt4, ldexp(1.0, -151)); // < -frac_size -> 0
  genc("ge4_overflow", fmt4, ldexp(1.0, 128));
  genc("ge4_dbl_max", fmt4, std::numeric_limits<double>::max());
  genc("ge4_snan", fmt4, frombits(0x7FF0000000000001ULL)); // payload dropped
  genc("ge4_negsnan", fmt4, frombits(0xFFF0000000000001ULL)); // sign kept
  genc("ge4_zero", fmt4, 0.0);
  genc("ge4_negzero", fmt4, frombits(0x8000000000000000ULL));
  genc("ge4_inf", fmt4, std::numeric_limits<double>::infinity());
  genc("ge8_pi", fmt8, 3.14);
  genc("ge8_neg7", fmt8, -7.0);
  genc("ge8_min_denorm", fmt8, frombits(0x0000000000000001ULL));

  // ---- FLOAT-OPINT2FLOAT-SIGN-0001 36-case value regression ----
  i2f("i2f4_pos7", fmt4, 0x00000007, 4);
  i2f("i2f8_pos7", fmt8, 0x00000007, 4);
  i2f("i2f4_zero", fmt4, 0x00000000, 4);
  i2f("i2f4_neg7", fmt4, 0xFFFFFFF9, 4);
  i2f("i2f8_neg7", fmt8, 0xFFFFFFF9, 4);
  i2f("i2f4_neg7_size1", fmt4, 0xF9, 1);
  i2f("i2f4_neg9_size2", fmt4, 0xFFF7, 2);
  i2f("i2f4_neg7_size8", fmt4, 0xFFFFFFFFFFFFFFF9ULL, 8);
  i2f("i2f8_neg1", fmt8, 0xFFFFFFFF, 4);
  i2f("i2f8_neg7_junk", fmt8, 0xABCDFFFFFFF9ULL, 4);
  i2f("i2f4_int32_min", fmt4, 0x80000000, 4);
  i2f("i2f4_int32_max", fmt4, 0x7FFFFFFF, 4);
  i2f("i2f4_2p24p1", fmt4, 0x01000001, 4);
  i2f("i2f8_int64_min", fmt8, 0x8000000000000000ULL, 8);
  i2f("i2f8_int64_min1", fmt8, 0x8000000000000001ULL, 8);
  i2f("i2f8_int64_max", fmt8, 0x7FFFFFFFFFFFFFFFULL, 8);
  f2f("f2f_4to8_onefive", fmt4, 0x3FC00000, fmt8);
  f2f("f2f_4to8_neg1", fmt4, 0xBF800000, fmt8);
  f2f("f2f_4to8_negzero", fmt4, 0x80000000, fmt8);
  f2f("f2f_4to8_nan", fmt4, 0x7FC00000, fmt8);
  f2f("f2f_4to8_negnan", fmt4, 0xFFC00000, fmt8);
  f2f("f2f_4to8_posinf", fmt4, 0x7F800000, fmt8);
  f2f("f2f_4to8_sub_min", fmt4, 0x00000001, fmt8);
  f2f("f2f_4to8_sub_max", fmt4, 0x007FFFFF, fmt8);
  f2f("f2f_8to4_neg1", fmt8, 0xBFF0000000000000ULL, fmt4);
  f2f("f2f_8to4_negthird", fmt8, 0xBFD5555555555555ULL, fmt4);
  f2f("f2f_8to4_tie_even", fmt8, 0x3FF0000010000000ULL, fmt4);
  f2f("f2f_8to4_above_tie", fmt8, 0x3FF0000018000000ULL, fmt4);
  f2f("f2f_8to4_negtie", fmt8, 0xBFF0000010000000ULL, fmt4);
  f2f("f2f_8to4_sub_out", fmt8, 0x3800000000000000ULL, fmt4);
  f2f("f2f_8to4_too_small", fmt8, 0x2100000000000000ULL, fmt4);
  f2f("f2f_8to4_dbl_max", fmt8, 0x7FEFFFFFFFFFFFFFULL, fmt4);
  f2f("f2f_8to4_negdbl_max", fmt8, 0xFFEFFFFFFFFFFFFFULL, fmt4);
  f2f("f2f_8to4_negnan", fmt8, 0xFFF8000000000000ULL, fmt4);
  f2f("f2f_8to4_neginf", fmt8, 0xFFF0000000000000ULL, fmt4);
  f2f("f2f_8to4_negzero", fmt8, 0x8000000000000000ULL, fmt4);
  return 0;
}

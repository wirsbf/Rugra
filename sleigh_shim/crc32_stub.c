#include <stdint.h>
#include "zlib.h"
typedef unsigned int uInt;
typedef unsigned long uLong;

#ifdef __cplusplus
extern "C" {
#endif

static uint32_t crc_table[256];
static int crc_table_ready = 0;

static void make_crc_table(void) {
    uint32_t c;
    for (uInt n = 0; n < 256; n++) {
        c = (uint32_t)n;
        for (int k = 0; k < 8; k++) {
            if (c & 1) c = 0xedb88320U ^ (c >> 1);
            else c = c >> 1;
        }
        crc_table[n] = c;
    }
    crc_table_ready = 1;
}

unsigned long crc32(unsigned long crc, const unsigned char *buf, uInt len) {
    if (!crc_table_ready) make_crc_table();
    crc = crc ^ 0xffffffffU;
    for (uInt i = 0; i < len; i++)
        crc = crc_table[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xffffffffU;
}

int compress2(unsigned char *dest, uLong *destLen,
              const unsigned char *source, uLong sourceLen, int level) {
    if (*destLen < sourceLen) return -5;
    for (uLong i = 0; i < sourceLen; i++) dest[i] = source[i];
    *destLen = sourceLen;
    return 0;
}

int uncompress(unsigned char *dest, uLong *destLen,
               const unsigned char *source, uLong sourceLen) {
    if (*destLen < sourceLen) return -5;
    for (uLong i = 0; i < sourceLen; i++) dest[i] = source[i];
    *destLen = sourceLen;
    return 0;
}

#ifdef __cplusplus
}
#endif

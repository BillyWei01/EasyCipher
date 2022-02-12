/*
 * Copyright (c) 1996, 2018, Oracle and/or its affiliates. All rights reserved.
 * ORACLE PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

/*
 * Portions Copyright (c) 1995  Colin Plumb.  All rights reserved.
 */

#include "rsa.h"
#include "random.h"

#include <stdlib.h>
#include <string.h>

// The library support 1024/2048 bits key now, the key takes 64 words(32bits for one word) at most.
// We reserve bytes for BigInt, for some middle calculation may use more than 64 words.
#define RSA_KEY_CAPACITY 68

#define KNUTH_POW2_THRESH_LEN  6
#define KNUTH_POW2_THRESH_ZEROS  3

typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;

typedef struct {
    u32 *value;
    int size;
} BigInt;

typedef struct {
    int is_dynamic_value;
    u32 *value;
    int intLen;
    int offset;
    int capacity;
} MutableBigInt;

static int bnExpModThreshTable[] = {7, 25, 81, 241, 673, 1793, 0x7fffffff};

void initBigInt(MutableBigInt *dst, u32 *buffer, int len, int capacity) {
    dst->is_dynamic_value = 0;
    dst->value = buffer;
    dst->intLen = len;
    dst->offset = 0;
    dst->capacity = capacity;
}

void compact(MutableBigInt *a) {
    int offset = a->offset;
    if (offset != 0) {
        u32 *value = a->value;
        memmove(value, value + offset, a->intLen << 2);
        a->offset = 0;
    }
}

// For 1024/2048 bits crypt, size reserve for MutableBigInt is enough, the check is just for robust.
void checkSize(MutableBigInt *a, int needSize) {
    if (a->capacity >= needSize) {
        return;
    }
    u32 *oldValue = a->value;
    a->value = (u32 *) malloc(needSize << 2);
    if (a->intLen != 0) {
        memcpy(a->value, oldValue + a->offset, a->intLen << 2);
    }
    a->offset = 0;
    a->capacity = needSize;
    if (a->is_dynamic_value == 1) {
        free(oldValue);
    } else {
        a->is_dynamic_value = 1;
    }
}

void copy(MutableBigInt *dst, MutableBigInt *src) {
    int n = src->intLen;
    checkSize(dst, n);
    u32 *s = src->value + src->offset;
    memcpy(dst->value, s, n << 2);
    dst->intLen = src->intLen;
    dst->offset = 0;
}

int numberOfLeadingZeros(u32 i) {
    if (i == 0)
        return 32;
    int n = 1;
    if (i >> 16 == 0) {
        n += 16;
        i <<= 16;
    }
    if (i >> 24 == 0) {
        n += 8;
        i <<= 8;
    }
    if (i >> 28 == 0) {
        n += 4;
        i <<= 4;
    }
    if (i >> 30 == 0) {
        n += 2;
        i <<= 2;
    }
    n -= i >> 31;
    return n;
}

int numberOfTrailingZeros(u32 i) {
    u32 y;
    if (i == 0) return 32;
    u32 n = 31;
    y = i << 16;
    if (y != 0) {
        n = n - 16;
        i = y;
    }
    y = i << 8;
    if (y != 0) {
        n = n - 8;
        i = y;
    }
    y = i << 4;
    if (y != 0) {
        n = n - 4;
        i = y;
    }
    y = i << 2;
    if (y != 0) {
        n = n - 2;
        i = y;
    }
    n -= ((i << 1) >> 31);
    return n;
}

int bitLengthForInt(int n) {
    return 32 - numberOfLeadingZeros(n);
}

int bitLength(const BigInt *bn) {
    int size = bn->size;
    if (size == 0) {
        return 0;
    }
    u32 lastWord = bn->value[0];
    return ((size - 1) << 5) + bitLengthForInt(lastWord);
}

void bigIntCopy(BigInt *dst, const BigInt *src) {
    int size = src->size;
    memcpy(dst->value, src->value, size << 2);
    dst->size = size;
}

/**
 * Returns the multiplicative inverse of val mod 2^64.  Assumes val is odd.
 */
static i64 inverseMod64(i64 val) {
    // Newton's iteration!
    i64 t = val;
    t *= 2 - val * t;
    t *= 2 - val * t;
    t *= 2 - val * t;
    t *= 2 - val * t;
    t *= 2 - val * t;
    // assert(t * val == 1);
    return t;
}

// shifts a up to len left n bits assumes no leading zeros, 0<=n<32
void primitiveLeftShift(u32 *a, int len, int n) {
    if (len == 0 || n == 0)
        return;
    int n2 = 32 - n;
    u32 c = a[0];
    for (int i = 0, m = i + len - 1; i < m; i++) {
        u32 b = c;
        c = a[i + 1];
        a[i] = (b << n) | (c >> n2);
    }
    a[len - 1] <<= n;
}

// shifts a up to len right n bits assumes no leading zeros, 0<n<32
static void primitiveRightShift(u32 *a, int len, int n) {
    if (len == 0 || n == 0) {
        return;
    }
    int n2 = 32 - n;
    u32 c = a[len - 1];
    for (int i = len - 1; i > 0; i--) {
        u32 b = c;
        c = a[i - 1];
        a[i] = (c << n2) | (b >> n);
    }
    a[0] >>= n;
}

/**
 * Left shift int array a up to len by n bits. Returns the array that
 * results from the shift since space may have to be reallocated.
 */
int leftShift(const BigInt *num, int n, u32 *out) {
    const u32 *a = num->value;
    int len = num->size;
    int nInts = ((u32) n) >> 5;
    int nBits = n & 0x1F;
    int bitsInHighWord = bitLengthForInt(a[0]);
    memcpy(out, a, len << 2);
    if (n <= (32 - bitsInHighWord)) {
        primitiveLeftShift(out, len, nBits);
        return len;
    } else {
        if (nBits <= (32 - bitsInHighWord)) {
            int resultLen = nInts + len;
            primitiveLeftShift(out, resultLen, nBits);
            return resultLen;
        } else {
            int resultLen = nInts + len + 1;
            primitiveRightShift(out, resultLen, 32 - nBits);
            return resultLen;
        }
    }
}

int compareArray(const u32 *a, const u32 *b, int len) {
    for (int i = 0; i < len; i++) {
        u32 x = a[i];
        u32 y = b[i];
        if (x < y)
            return -1;
        if (y > x)
            return 1;
    }
    return 0;
}

/**
 * Compare the magnitude of two MutableBigIntegers. Returns -1, 0 or 1
 * as this MutableBigInt is numerically less than, equal to, or greater than b.
 */
int compareMutableBigInt(MutableBigInt *a, MutableBigInt *b) {
    int bLen = b->intLen;
    int aLen = a->intLen;
    if (aLen != bLen) {
        return aLen - bLen;
    }
    return compareArray(a->value + a->offset, b->value + b->offset, aLen);
}

int compareBigInt(const BigInt *a, const BigInt *b) {
    int aLen = a->size;
    int bLen = b->size;
    if (aLen != bLen) {
        return aLen - bLen;
    }
    return compareArray(a->value, b->value, aLen);
}

void normalize(MutableBigInt *a) {
    if (a->intLen == 0) {
        a->offset = 0;
        return;
    }

    int index = a->offset;
    if (a->value[index] != 0)
        return;

    int indexBound = index + a->intLen;
    do {
        index++;
    } while (index < indexBound && a->value[index] == 0);

    int numZeros = index - a->offset;
    a->intLen -= numZeros;
    a->offset = (a->intLen == 0 ? 0 : a->offset + numZeros);
}

/**
* This method is used for division of an n word dividend by a one word
* divisor. The one word divisor is specified by divisor.
* Return the remainder of the division is returned.
*/
u32 divideOneWord(MutableBigInt *a, u32 divisor, MutableBigInt *quotient) {
    u64 divisorLong = divisor;
    // Special case of one word dividend
    if (a->intLen == 1) {
        u64 dividendValue = a->value[a->offset];
        return dividendValue % divisorLong;
    }

    // Normalize the divisor
    int shift = numberOfLeadingZeros(divisor);
    u32 rem = a->value[a->offset];
    u64 remLong = rem;
    if (remLong >= divisorLong) {
        rem = remLong % divisorLong;
        remLong = rem;
    }
    int xlen = a->intLen;
    while (--xlen > 0) {
        u64 dividendEstimate = (remLong << 32) | (a->value[a->offset + a->intLen - xlen]);
        rem = dividendEstimate % divisorLong;
        remLong = rem;
    }

    // Unnormalize
    if (shift > 0)
        return rem % divisor;
    else
        return rem;
}

int min(int a, int b) {
    return a < b ? a : b;
}

/**
 * Return the index of the lowest set bit in this MutableBigInt. If the
 * magnitude of this MutableBigInt is zero, -1 is returned.
 */
int getLowestSetBit(MutableBigInt *a) {
    if (a->intLen == 0)
        return -1;
    int j, b;
    int offset = a->offset;
    for (j = a->intLen - 1; (j > 0) && (a->value[j + offset] == 0); j--);
    b = a->value[j + offset];
    if (b == 0)
        return -1;
    return ((a->intLen - 1 - j) << 5) + numberOfTrailingZeros(b);
}

/**
 * Right shift this MutableBigInt n bits. The MutableBigInt is left
 * in normal form.
 */
void bigIntRightShift(MutableBigInt *a, u32 n) {
    if (a->intLen == 0)
        return;
    u32 nInts = n >> 5;
    int nBits = (int) n & 0x1F;
    a->intLen -= nInts;
    if (nBits == 0)
        return;
    int bitsInHighWord = bitLengthForInt(a->value[a->offset]);
    if (nBits >= bitsInHighWord) {
        primitiveRightShift(a->value + a->offset, a->intLen, 32 - nBits);
        a->intLen--;
    } else {
        primitiveRightShift(a->value + a->offset, a->intLen, nBits);
    }
}

void bigIntLeftShift(MutableBigInt *a, u32 n) {
    if (a->intLen == 0)
        return;
    int nInts = n >> 5;
    int nBits = (int) n & 0x1F;
    int bitsInHighWord = bitLengthForInt(a->value[a->offset]);

    // If shift can be done without moving words, do so
    if (n <= (32 - bitsInHighWord)) {
        primitiveLeftShift(a->value + a->offset, a->intLen, nBits);
        return;
    }

    int newLen = a->intLen + nInts + 1;
    if (nBits <= (32 - bitsInHighWord))
        newLen--;
    if (a->capacity < newLen) {
        checkSize(a, newLen);
    } else if (a->capacity - a->offset >= newLen) {
        // Use space on right
        int len = a->intLen;
        int offset = a->offset;
        for (int i = 0; i < newLen - len; i++)
            a->value[offset + len + i] = 0;
    } else {
        // Must use space on left
        int len = a->intLen;
        int offset = a->offset;
        for (int i = 0; i < len; i++)
            a->value[i] = a->value[offset + i];
        for (int i = len; i < newLen; i++)
            a->value[i] = 0;
        offset = 0;
    }
    a->intLen = newLen;
    if (nBits == 0)
        return;
    if (nBits <= (32 - bitsInHighWord))
        primitiveLeftShift(a->value + a->offset, a->intLen, nBits);
    else
        primitiveRightShift(a->value + a->offset, a->intLen, 32 - nBits);
}

void copyAndShift(const u32 *src, int srcFrom, int srcLen, u32 *dst, int dstFrom, int shift) {
    u32 n2 = 32 - shift;
    u32 c = src[srcFrom];
    for (int i = 0; i < srcLen - 1; i++) {
        u32 b = c;
        c = src[++srcFrom];
        dst[dstFrom + i] = (b << shift) | (c >> n2);
    }
    dst[dstFrom + srcLen - 1] = c << shift;
}

u32 mulsub(u32 *q, const u32 *a, u32 x, int len, int offset) {
    u64 xLong = x;
    u64 carry = 0;
    offset += len;

    for (int j = len - 1; j >= 0; j--) {
        u64 product = ((u64) a[j]) * xLong + carry;
        u64 difference = q[offset] - product;
        q[offset--] = difference;
        carry = (product >> 32) + ((u32) difference > (~(u32) product) ? 1 : 0);
    }
    return carry;
}

int divadd(const u32 *a, int aLen, u32 *result, int offset) {
    u64 carry = 0;
    for (int j = aLen - 1; j >= 0; j--) {
        u64 sum = ((u64) a[j]) + ((u64) result[j + offset]) + carry;
        result[j + offset] = (u32) sum;
        carry = sum >> 32;
    }
    return (int) carry;
}

void divideMagnitude(MutableBigInt *a, MutableBigInt *div, MutableBigInt *rem) {
    // assert div.intLen > 1
    // D1 normalize the divisor
    int shift = numberOfLeadingZeros(div->value[div->offset]);
    int dlen = div->intLen;

    int capacity = RSA_KEY_CAPACITY << 1;
    u32 buffer[capacity];
    u32 *divisor = (capacity >= dlen) ? buffer : malloc(sizeof(int) * dlen);

    // Remainder starts as dividend with space for a leading zero
    if (shift > 0) {
        memset(divisor, 0, dlen << 2);
        copyAndShift(div->value, div->offset, dlen, divisor, 0, shift);
        if (numberOfLeadingZeros(a->value[a->offset]) >= shift) {
            int needSize = a->intLen + 1;
            checkSize(rem, needSize);
            rem->intLen = a->intLen;
            rem->offset = 1;
            copyAndShift(a->value, a->offset, a->intLen, rem->value, 1, shift);
        } else {
            int needSize = a->intLen + 2;
            checkSize(rem, needSize);
            u32 *remarr = rem->value;
            rem->intLen = a->intLen + 1;
            rem->offset = 1;
            int rFrom = a->offset;
            u32 c = 0;
            int n2 = 32 - shift;
            for (int i = 1; i < a->intLen + 1; i++, rFrom++) {
                u32 b = c;
                c = a->value[rFrom];
                remarr[i] = (b << shift) | (c >> n2);
            }
            remarr[a->intLen + 1] = c << shift;
        }
    } else {
        memcpy(divisor, div->value + div->offset, div->intLen << 2);
        int needSize = a->intLen + 1;
        checkSize(rem, needSize);
        memcpy(rem->value + 1, a->value + a->offset, a->intLen << 2);
        rem->intLen = a->intLen;
        rem->offset = 1;
    }

    int nlen = rem->intLen;
    int limit = nlen - dlen + 1;

    // Must insert leading 0 in rem if its length did not change
    if (rem->intLen == nlen) {
        rem->offset = 0;
        rem->value[0] = 0;
        rem->intLen++;
    }

    u32 dh = divisor[0];
    u64 dhLong = dh;
    u32 dl = divisor[1];

    // D2 Initialize j
    for (int j = 0; j < limit - 1; j++) {
        // D3 Calculate qhat
        // estimate qhat
        u32 qhat = 0;
        u32 qrem = 0;
        u32 skipCorrection = 0;
        u32 nh = rem->value[j + rem->offset];
        u32 nm = rem->value[j + 1 + rem->offset];

        if (nh == dh) {
            qhat = ~0;
            qrem = nh + nm;
            skipCorrection = qrem < nh;
        } else {
            u64 nChunk = (((u64) nh) << 32) | ((u64) nm);
            qhat = nChunk / dhLong;
            qrem = nChunk - (qhat * dhLong);
        }

        if (qhat == 0)
            continue;

        if (!skipCorrection) { // Correct qhat
            u64 nl = rem->value[j + 2 + rem->offset];
            u64 rs = (((u64) qrem) << 32) | nl;
            u64 estProduct = ((u64) dl) * ((u64) qhat);

            if (estProduct > rs) {
                qhat--;
                qrem = (((u64) qrem) + dhLong);
                if (((u64) qrem) >= dhLong) {
                    estProduct -= dl;
                    rs = (((u64) qrem) << 32) | nl;
                    if (estProduct > rs)
                        qhat--;
                }
            }
        }

        // D4 Multiply and subtract
        int offset = j + rem->offset;
        rem->value[offset] = 0;
        u32 borrow = mulsub(rem->value, divisor, qhat, dlen, offset);

        // D5 Test remainder
        if (borrow > nh) {
            // D6 Add back
            divadd(divisor, dlen, rem->value, offset + 1);
            qhat--;
        }
    } // D7 loop on j
    // D3 Calculate qhat
    // estimate qhat
    u32 qhat = 0;
    u32 qrem = 0;
    u32 skipCorrection = 0;
    u32 nh = rem->value[limit - 1 + rem->offset];
    u32 nm = rem->value[limit + rem->offset];

    if (nh == dh) {
        qhat = ~0;
        qrem = nh + nm;
        skipCorrection = qrem < nh;
    } else {
        u64 nChunk = (((u64) nh) << 32) | nm;
        qhat = nChunk / dhLong;
        qrem = nChunk - (qhat * dhLong);
    }
    if (qhat != 0) {
        if (!skipCorrection) { // Correct qhat
            u64 nl = rem->value[limit + 1 + rem->offset];
            u64 rs = (((u64) qrem) << 32) | nl;
            u64 estProduct = ((u64) dl) * ((u64) qhat);

            if (estProduct > rs) {
                qhat--;
                qrem = (int) (((u64) qrem) + dhLong);
                if (((u64) qrem) >= dhLong) {
                    estProduct -= dl;
                    rs = (((u64) qrem) << 32) | nl;
                    if (estProduct > rs)
                        qhat--;
                }
            }
        }

        // D4 Multiply and subtract
        int offset = limit - 1 + rem->offset;
        rem->value[offset] = 0;

        u32 borrow = mulsub(rem->value, divisor, qhat, dlen, offset);
        // D5 Test remainder
        if (borrow > nh) {
            // D6 Add back
            divadd(divisor, dlen, rem->value, offset + 1);
            qhat--;
        }
    }

    // D8 Unnormalize
    if (shift > 0)
        bigIntRightShift(rem, shift);
    normalize(rem);

    if (divisor != buffer) {
        free(divisor);
    }
}

/**
 * Uses Algorithm D in Knuth section 4.3.1.
 * Many optimizations to that algorithm have been adapted from the Colin
 * Plumb C library.
 * It special cases one word divisors for speed. The content of b is not changed.
 */
CryptResult divide(MutableBigInt *a, MutableBigInt *b, MutableBigInt *remainder) {
    if (b->intLen == 0) {
        return FAILED_UNKNOWN;
    }

    // Dividend is zero
    if (a->intLen == 0) {
        remainder->intLen = 0;
        return CRYPT_SUCCESS;
    }
    int cmp = compareMutableBigInt(a, b);
    if (cmp < 0) {
        copy(remainder, a);
        return CRYPT_SUCCESS;
    }

    if (cmp == 0) {
        remainder->intLen = 0;
        remainder->offset = 0;
        return CRYPT_SUCCESS;
    }

    if (b->intLen == 1) {
        u32 r = divideOneWord(a, b->value[b->offset], NULL);
        if (r == 0) {
            remainder->intLen = 0;
        } else {
            remainder->intLen = 1;
            remainder->value[0] = r;
        }
        remainder->offset = 0;
        return CRYPT_SUCCESS;
    }

    // Cancel common powers of two if we're above the KNUTH_POW2_* thresholds
    if (a->intLen >= KNUTH_POW2_THRESH_LEN) {
        int trailingZeroBits = min(getLowestSetBit(a), getLowestSetBit(b));
        if (trailingZeroBits >= KNUTH_POW2_THRESH_ZEROS * 32) {
            compact(a);
            compact(b);
            bigIntRightShift(a, trailingZeroBits);
            bigIntRightShift(b, trailingZeroBits);
            int ret = divide(a, b, remainder);
            bigIntLeftShift(remainder, trailingZeroBits);
            return ret;
        }
    }

    divideMagnitude(a, b, remainder);
    return CRYPT_SUCCESS;
}

u32 mulAdd(u32 *out, int outLen, const u32 *in, int offset, int len, u32 k) {
    u64 kLong = k;
    u64 carry = 0;

    offset = outLen - offset - 1;
    for (int j = len - 1; j >= 0; j--) {
        u64 product = ((u64) in[j]) * kLong + ((u64) out[offset]) + carry;
        out[offset--] = product;
        carry = product >> 32;
    }
    return (u32) carry;
}

int addOne(u32 *a, int aLen, int offset, int mlen, u32 carry) {
    offset = aLen - 1 - mlen - offset;
    u64 t = ((u64) a[offset]) + ((u64) carry);

    a[offset] = (int) t;
    if ((t >> 32) == 0)
        return 0;
    while (--mlen >= 0) {
        if (--offset < 0) {
            return 1;
        } else {
            a[offset]++;
            if (a[offset] != 0)
                return 0;
        }
    }
    return 1;
}

void squareToLen(u32 *x, int len, u32 *z, int zlen) {
    // Store the squares, right shifted one bit (i.e., divided by 2)
    u32 lastProductLowWord = 0;
    for (int j = 0, i = 0; j < len; j++) {
        u64 piece = x[j];
        u64 product = piece * piece;
        z[i++] = (lastProductLowWord << 31) | (u32) (product >> 33);
        z[i++] = (u32) (product >> 1);
        lastProductLowWord = (u32) product;
    }

    // Add in off-diagonal sums
    for (int i = len, offset = 1; i > 0; i--, offset += 2) {
        u32 t = x[i - 1];
        t = mulAdd(z, zlen, x, offset, i - 1, t);
        addOne(z, zlen, offset - 1, i, t);
    }

    // Shift back up and set low bit
    primitiveLeftShift(z, zlen, 1);
    z[zlen - 1] |= x[len - 1] & 1;
}

void multiplyToLen(const u32 *x, int xlen, const u32 *y, int ylen, u32 *z) {
    int xstart = xlen - 1;
    int ystart = ylen - 1;

    u64 carry = 0;
    for (int j = ystart, k = ystart + 1 + xstart; j >= 0; j--, k--) {
        u64 product = ((u64) y[j]) * ((u64) x[xstart]) + carry;
        z[k] = (int) product;
        carry = product >> 32;
    }
    z[xstart] = carry;

    for (int i = xstart - 1; i >= 0; i--) {
        carry = 0;
        for (int j = ystart, k = ystart + 1 + i; j >= 0; j--, k--) {
            u64 product = ((u64) y[j]) * ((u64) x[i]) + ((u64) z[k]) + carry;
            z[k] = product;
            carry = product >> 32;
        }
        z[i] = carry;
    }
}

int subN(u32 *a, const u32 *b, int len) {
    i64 sum = 0;
    while (--len >= 0) {
        sum = (i64) ((u64) a[len]) - (i64) ((u64) b[len]) + (sum >> 32);
        a[len] = sum;
    }
    return (int) (sum >> 32);
}

int intArrayCmpToLen(const u32 *arg1, const u32 *arg2, int len) {
    for (int i = 0; i < len; i++) {
        u32 b1 = arg1[i];
        u32 b2 = arg2[i];
        if (b1 < b2)
            return -1;
        if (b1 > b2)
            return 1;
    }
    return 0;
}

void montReduce(u32 *n, int zlen, const u32 *mod, int mlen, u32 inv) {
    int c = 0;
    int len = mlen;
    int offset = 0;

    do {
        u32 nEnd = n[zlen - 1 - offset];
        u32 carry = mulAdd(n, zlen, mod, offset, mlen, inv * nEnd);
        c += addOne(n, zlen, offset, mlen, carry);
        offset++;
    } while (--len > 0);

    while (c > 0)
        c += subN(n, mod, mlen);

    while (intArrayCmpToLen(n, mod, mlen) >= 0)
        subN(n, mod, mlen);
}

void montgomerySquare(u32 *x, const u32 *mod, int modLen, i64 inv, u32 *product) {
    int zlen = modLen << 1;
    squareToLen(x, modLen, product, zlen);
    montReduce(product, zlen, mod, modLen, (int) inv);
}

void montgomeryMultiply(u32 *x, u32 *y, const u32 *mod, int modLen, i64 inv, u32 *product) {
    int zlen = modLen << 1;
    multiplyToLen(x, modLen, y, modLen, product);
    montReduce(product, zlen, mod, modLen, (int) inv);
}

CryptResult modPow(const BigInt *base, const BigInt *exponent, const BigInt *modulus, BigInt *out) {
    if (exponent->size == 1 && exponent->value[0] == 1) {
        bigIntCopy(out, base);
        return CRYPT_SUCCESS;
    }

    int modLen = modulus->size;
    int expLen = exponent->size;
    const u32 *p_mod = modulus->value;
    const u32 *p_exp = exponent->value;
    int modBytes = modLen << 2;

    // Compute the modular inverse of the least significant 64-bit
    // digit of the modulus
    i64 n0 = ((u64) p_mod[modLen - 1]) + (((u64) p_mod[modLen - 2]) << 32);
    i64 inv = -inverseMod64(n0);

    // assert(modLen <= RSA_KEY_CAPACITY);
    int doubleCapacity = RSA_KEY_CAPACITY << 1;
    u32 aBuffer[doubleCapacity];
    u32 bBuffer[doubleCapacity];
    u32 rBuffer[doubleCapacity];

    memset(aBuffer, 0, doubleCapacity << 2);
    memset(bBuffer, 0, doubleCapacity << 2);

    u32 *a = aBuffer;
    int aLen = leftShift(base, modLen << 5, a);

    MutableBigInt a2, b2, r;
    initBigInt(&a2, a, aLen, doubleCapacity);
    initBigInt(&b2, modulus->value, modulus->size, modulus->size);
    initBigInt(&r, rBuffer, 0, doubleCapacity);
    normalize(&b2);

    int ret = divide(&a2, &b2, &r);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Select an appropriate window size
    int wbits = 0;
    int ebits = bitLength(exponent);
    // if exponent is 65537 (0x10001), use minimum window size
    if ((ebits != 17) || (p_exp[0] != 65537)) {
        while (ebits > bnExpModThreshTable[wbits]) {
            wbits++;
        }
    }

    // Allocate table for precomputed odd powers of base in Montgomery form
    int table_size = 1 << wbits;
    int tableCapacity = modLen << 1;
    u32 *table_buffer = malloc((tableCapacity << 2) * table_size);
    if (table_buffer == NULL) {
        return FAILED_OUT_OF_MEMORY;
    }

    // Max wbits is 6, so max table size will be 64
    u32 *table[64];
    u32 *p_table = table_buffer;
    for (int i = 0; i < table_size; i++) {
        table[i] = p_table;
        p_table += tableCapacity;
    }

    int rLen = r.intLen;
    memcpy(table[0], r.value + r.offset, rLen << 2);
    if (rLen < modLen) {
        memset(table[0] + rLen, 0, (modLen - rLen) << 2);
    }

    u32 *b = bBuffer;
    montgomerySquare(table[0], p_mod, modLen, inv, b);

    u32 *t = b;
    for (int i = 1; i < table_size; i++) {
        montgomeryMultiply(t, table[i - 1], p_mod, modLen, inv, table[i]);
    }

    // Pre load the window that slides over the exponent
    u32 bitpos = 1 << ((ebits - 1) & (32 - 1));

    u32 buf = 0;
    int elen = expLen;
    int eIndex = 0;
    for (int i = 0; i <= wbits; i++) {
        buf = (buf << 1) | (((p_exp[eIndex] & bitpos) != 0) ? 1 : 0);
        bitpos >>= 1;
        if (bitpos == 0) {
            eIndex++;
            bitpos = 1 << (32 - 1);
            elen--;
        }
    }

    ebits--;
    int multpos = ebits - wbits;
    while ((buf & 1) == 0) {
        buf >>= 1;
        multpos++;
    }
    u32 *mult = table[buf >> 1];
    buf = 0;
    int isone = (multpos == ebits) ? 0 : 1;

    // The main loop
    while (1) {
        ebits--;
        // Advance the window
        buf <<= 1;

        if (elen != 0) {
            buf |= ((p_exp[eIndex] & bitpos) != 0) ? 1 : 0;
            bitpos >>= 1;
            if (bitpos == 0) {
                eIndex++;
                bitpos = 1 << (32 - 1);
                elen--;
            }
        }

        // Examine the window for pending multiplies
        if ((buf & table_size) != 0) {
            multpos = ebits - wbits;
            while ((buf & 1) == 0) {
                buf >>= 1;
                multpos++;
            }
            mult = table[buf >> 1];
            buf = 0;
        }

        // Perform multiply
        if (ebits == multpos) {
            if (isone) {
                memcpy(b, mult, modBytes);
                isone = 0;
            } else {
                t = b;
                montgomeryMultiply(t, mult, p_mod, modLen, inv, a);
                t = a;
                a = b;
                b = t;
            }
        }

        // Check if done
        if (ebits == 0)
            break;

        // Square the input
        if (!isone) {
            t = b;
            montgomerySquare(t, p_mod, modLen, inv, a);
            t = a;
            a = b;
            b = t;
        }
    }

    // Convert result out of Montgomery form and return
    u32 *t2 = b != aBuffer ? aBuffer : bBuffer;
    memset(t2, 0, modBytes);
    memcpy(t2 + modLen, b, modBytes);
    montReduce(t2, modLen << 1, p_mod, modLen, (int) inv);
    memcpy(out->value, t2, modBytes);
    out->size = modLen;

    free(table_buffer);

    return CRYPT_SUCCESS;
}

void bytesToBigInt(const ByteArray *in, BigInt *out) {
    uint8_t *bytes = in->value;
    int byteLength = in->len;

    // Find first nonzero byte
    int keep;
    for (keep = 0; keep < byteLength && bytes[keep] == 0; keep++);

    int intLength = ((byteLength - keep) + 3) >> 2;
    out->size = intLength;
    u32 *value = out->value;
    if (value == NULL) {
        return;
    }
    int b = byteLength - 1;
    for (int i = intLength - 1; i >= 0; i--) {
        value[i] = bytes[b--] & 0xff;
        int bytesRemaining = b - keep + 1;
        int bytesToTransfer = bytesRemaining < 3 ? bytesRemaining : 3;
        for (int j = 8; j <= (bytesToTransfer << 3); j += 8)
            value[i] |= ((bytes[b--] & 0xff) << j);
    }
}

void removeZero(uint8_t *a, int size) {
    for (int i = 0; i < size; i++) {
        uint8_t x = a[i];
        if (x == 0) {
            x = i ^ size;
            if (i > 0) {
                x ^= a[i - 1];
            }
            if ((i + 1) < size) {
                x ^= a[i + 1];
            }
            if (x != 0) {
                a[i] = x;
            } else {
                a[i] = size < 0xFF ? size : 1;
            }
        }
    }
}

/*
    EB = 00 || BT || PS || 00 || DATA
    BT: The block type
    BT = 01, when the key is private
    BT = 02, when the key is public
    PS: The padding string
    when BT = 01，PS padding with 0xFF；
    when BT = 02，PS padding with non zero random string；
 */
void paddingInput(uint8_t *block, int blockSize, int dataLen, KeyType type) {
    int paddingLen = blockSize - dataLen - 3;
    block[0] = 0;
    block[1] = type;
    if (type == PRIVATE_KEY) {
        memset(block + 2, 0xFF, paddingLen);
    } else {
        getRandom(block + 2, paddingLen);
        removeZero(block + 2, paddingLen);
    }
    block[2 + paddingLen] = 0;
}

CryptResult rsa_crypt(const ByteArray *input,
                      const RSAKey *key,
                      const CipherMode mode,
                      ByteArray *output) {
    const int sizeLimit = RSA_KEY_CAPACITY << 2;
    if (input == NULL || input->len > sizeLimit || output == NULL) {
        return FAILED_INVALID_INPUT;
    }
    if (key == NULL) {
        return FAILED_INVALID_KEY;
    }
    ByteArray *exponent = key->exponent;
    ByteArray *modulus = key->modulus;
    if (exponent == NULL ||
        modulus == NULL ||
        exponent->len > sizeLimit ||
        modulus->len > sizeLimit) {
        return FAILED_INVALID_KEY;
    }

    u32 buffer[4][RSA_KEY_CAPACITY];
    BigInt base, exp, mod, result;
    base.value = buffer[0];
    exp.value = buffer[1];
    mod.value = buffer[2];
    result.value = buffer[3];

    bytesToBigInt(exponent, &exp);
    bytesToBigInt(modulus, &mod);

    // Only accept keys with 1024 bits or 2048 bits.
    // Modulus must be odd.
    // Exponent must not be zero.
    // Exponent must less then modulus.
    int modLen = mod.size;
    if ((modLen != 32 && modLen != 64) ||
        (mod.value[modLen - 1] & 1) == 0
        || exp.size == 0
        || compareBigInt(&exp, &mod) >= 0) {
        return FAILED_INVALID_KEY;
    }

    if (compareBigInt(&exp, &mod) >= 0) {
        return FAILED_INVALID_KEY;
    }

    int blockSize = modLen << 2;
    int inputLen = input->len;
    if (mode == ENCRYPT) {
        if (inputLen > (blockSize - 11)) {
            return FAILED_INPUT_TOO_LARGE;
        }
    } else {
        if (inputLen != blockSize) {
            return FAILED_INVALID_INPUT;
        }
    }

    if (mode == ENCRYPT) {
        uint8_t block[256];
        paddingInput(block, blockSize, inputLen, key->key_type);
        memcpy(block + (blockSize - inputLen), input->value, inputLen);
        ByteArray tmp;
        tmp.value = block;
        tmp.len = blockSize;
        bytesToBigInt(&tmp, &base);
    } else {
        bytesToBigInt(input, &base);
    }

    if (compareBigInt(&base, &mod) > 0) {
        return FAILED_INVALID_INPUT;
    }

    int ret = modPow(&base, &exp, &mod, &result);

    uint8_t *p = output->value;
    u32 *r = result.value;
    for (int i = 0; i < modLen; i++) {
        u32 x = r[i];
        p[0] = x >> 24;
        p[1] = x >> 16;
        p[2] = x >> 8;
        p[3] = x;
        p += 4;
    }

    if (mode == ENCRYPT) {
        output->len = blockSize;
    } else {
        p = output->value;
        // check if the first bytes is 0, and encrypt type is different to decrypt key
        KeyType encryptType = (key->key_type == PRIVATE_KEY) ? PUBLIC_KEY : PRIVATE_KEY;
        if (!(p[0] == 0 && p[1] == encryptType)) {
            return FAILED_INVALID_INPUT;
        }
        int i = 2;
        for (; i < blockSize && p[i] != 0; i++) {
        }

        int valid = 1;
        if (i < 10 || i == blockSize) {
            valid = 0;
        } else {
            if (encryptType == PRIVATE_KEY) {
                for (int j = 2; j < i; j++) {
                    if (p[j] != 0xFF) {
                        valid = 0;
                        break;
                    }
                }
            }
        }
        if (valid != 1) {
            return FAILED_INVALID_INPUT;
        }
        i++;
        output->len = blockSize - i;
        if (blockSize != i) {
            memmove(output->value, p + i, output->len);
        }
    }

    return ret;
}

/*
   This file contains several source code (with modification).

----------------------------------------------------------------------------
SipHash:
   SipHash reference C implementation
   Copyright (c) 2012-2021 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.
   You should have received a copy of the CC0 Public Domain Dedication along
   with
   this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.

   Source Link:
   https://github.com/veorq/SipHash/blob/master/siphash.c

----------------------------------------------------------------------------
 MurmurHash:
    MurmurHash was written by Austin Appleby, and is placed in the public domain.
    The author hereby disclaims copyright to this source code.

    Source Link:
    https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
----------------------------------------------------------------------------
EasyEcc:
  Copyright (c) 2013, Kenneth MacKay

  Source Link:
  https://github.com/jestan/easy-ecc

----------------------------------------------------------------------------
  Copyright (c) 2021-2022 Billy Wei <across_horizon@qq.com>

  EasyEcc use the system's api to get the random bytes.
  In case of reading '/dev/urandom' and '/dev/random' failed, we need a backup to generate random bytes.

  We could collect some variables as random seed.
  The variables include time, CUP clock, pid, tid, array size, and uninitialized value.
  And use two strategies to discrete and iterate the seed.
  1. Hash (SipHash and MurmurHash)
  2. srand()/rand()

  We expected the random bytes to be non-repetitive and unpredictable.
 */


#if (defined(_WIN32) || defined(_WIN64))
/* Windows */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static int getRandom(uint8_t *value, int size)
{
    HCRYPTPROV l_prov;
    if(!CryptAcquireContext(&l_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return 0;
    }

    CryptGenRandom(l_prov, size, (BYTE *)value);
    CryptReleaseContext(l_prov, 0);

    return 1;
}

#else
/* Assume that we are using a POSIX-like system with /dev/urandom or /dev/random. */

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>

/*  SipHash-2-4 */
#ifndef cROUNDS
#define cROUNDS 2
#endif
#ifndef dROUNDS
#define dROUNDS 4
#endif

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND                                                               \
    do {                                                                       \
        v0 += v1;                                                              \
        v1 = ROTL(v1, 13);                                                     \
        v1 ^= v0;                                                              \
        v0 = ROTL(v0, 32);                                                     \
        v2 += v3;                                                              \
        v3 = ROTL(v3, 16);                                                     \
        v3 ^= v2;                                                              \
        v0 += v3;                                                              \
        v3 = ROTL(v3, 21);                                                     \
        v3 ^= v0;                                                              \
        v2 += v1;                                                              \
        v1 = ROTL(v1, 17);                                                     \
        v1 ^= v2;                                                              \
        v2 = ROTL(v2, 32);                                                     \
    } while (0)

uint64_t siphash(const uint64_t in, const uint64_t k0, const uint64_t k1) {
    uint64_t v0 = 0x736f6d6570736575ULL;
    uint64_t v1 = 0x646f72616e646f6dULL;
    uint64_t v2 = 0x6c7967656e657261ULL;
    uint64_t v3 = 0x7465646279746573ULL;
    uint64_t b = ((uint64_t) 8) << 56;
    uint64_t m;
    int i;

    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    m = in;
    v3 ^= m;

    for (i = 0; i < cROUNDS; ++i)
        SIPROUND;

    v0 ^= m;
    v3 ^= b;

    for (i = 0; i < cROUNDS; ++i)
        SIPROUND;

    v0 ^= b;
    v2 ^= 0xff;

    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    b = v0 ^ v1 ^ v2 ^ v3;
    return b;
}

uint64_t murmurHash64(const uint64_t key, const uint64_t seed) {
    const uint64_t m = 0xc6a4a7935bd1e995;
    const int r = 47;
    uint64_t h = seed ^(m << 3);
    uint64_t k = key;
    k *= m;
    k ^= k >> r;
    k *= m;
    h ^= k;
    h *= m;
    h ^= h >> r;
    h *= m;
    h ^= h >> r;
    return h;
}


/**
 * Fill random bytes to array.
 *
 * The function combine several variables as random seed,
 * with two hash functions and one pseudorandom function to discrete and iterate the seed.
 *
 * @param value The array to fill random bytes.
 * @param size The size to fill.
 */
void fillRandom(uint8_t *value, int size) {
    if (size <= 0) {
        return;
    }

    uint64_t s, u;
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret == 0) {
        s = tv.tv_sec;
        u = tv.tv_usec;
    } else {
        s = time(NULL);
        u = clock();
    }

    uint64_t thread = pthread_self();
    int tid = gettid();

    // Local array value, uninitialized, with the value of last written
    // (may be written by this function or other process).
    uint64_t a[2];

    uint64_t k1 = clock();
    uint64_t k2 = s * (u + 1);
    uint64_t k3 = (thread + tid) ^a[0];
    uint64_t k4 = size ^a[1];

    // Use the same rand seed in one second.
    static uint64_t last_time = 1;
    if (last_time != s) {
        uint64_t tmp[1];
        k4 ^= tmp[0];
        // Not to use rand() before call srand()
        if (last_time == 1) {
            k4 ^= getpid();
        } else {
            k4 ^= (uint64_t) rand();
        }
        uint64_t k = (k1 + k2) ^(k3 + k4);
        srand((k >> 32) ^ k);
        last_time = s;
    }

    uint64_t r = rand() ^(rand() << 16);
    k1 ^= r << 56;
    k2 ^= ((r >> 8) & 0xff) << 48;
    k3 ^= ((r >> 16) & 0xff) << 40;
    k4 ^= ((r >> 24) & 0xff) << 32;
    uint64_t ka[] = {k1, k2, k3, k4};

    int n = size >> 3;
    int remain = size & 7;
    uint64_t *p = (uint64_t *) value;
    uint64_t h = siphash(k1, k2, k3 ^ k4);
    for (int i = 0; i < n; i++) {
        p[i] = h;
        if (i < n || remain > 0) {
            int x = i & 3;
            int y = (i + 1) & 3;
            ka[x] ^= ka[y] * (rand() + n) + i;
            h = murmurHash64(h, ka[x]);
        }
    }
    if (remain > 0) {
        for (int i = size - remain; i < size; i++) {
            value[i] = (char) h;
            h >>= 8;
        }
    }

    // Set random value to a,
    // if next time enter this function with same start address,
    // we could have a different value.
    a[0] = ka[0] ^ ka[1];
    a[1] = ka[2] ^ ka[3];
}

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

int getRandom(uint8_t *out, int size) {
    uint8_t *p_value = out;
    int left = size;

    int l_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (l_fd == -1) {
        l_fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
        if (l_fd == -1) {
            fillRandom(p_value, left);
            return 1;
        }
    }

    while (left > 0) {
        int l_read = read(l_fd, p_value, left);
        if (l_read <= 0) { // read failed
            close(l_fd);
            fillRandom(p_value + (size - left), left);
            return 1;
        }
        left -= l_read;
        p_value += l_read;
    }

    close(l_fd);
    return 1;
}

#endif /* POSIX-like */
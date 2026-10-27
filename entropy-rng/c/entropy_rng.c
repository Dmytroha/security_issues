/* entropy_rng.c - see entropy_rng.h for the design overview. Linux, C11. */
#define _GNU_SOURCE
#include "entropy_rng.h"
#include "erng_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#define ERNG_X86 1
#endif

#define SEED_ENTROPY_BITS   256              /* security strength of HMAC-DRBG-SHA256 */
#define RESEED_INTERVAL     (1u << 16)       /* generate calls between automatic reseeds */
#define JITTER_MAX_CREDIT   1.0              /* never credit more than 1 bit per jitter sample */
#define JITTER_STARTUP      16384            /* samples for the start-up entropy estimate */
#define HWRNG_PATH          "/dev/hwrng"

static void wipe(void *p, size_t n) { explicit_bzero(p, n); }

/* ======================================================================== */
/* SHA-256 (FIPS 180-4)                                                     */
/* ======================================================================== */

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, k, t1, t2;
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; k = h[7];
    for (int i = 0; i < 64; i++) {
        t1 = k + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
    wipe(w, sizeof w);
}

void erng_sha256_init(erng_sha256 *c)
{
    static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(c->h, iv, sizeof iv);
    c->len = 0;
    c->used = 0;
}

void erng_sha256_update(erng_sha256 *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    c->len += n;
    if (c->used) {
        size_t take = 64 - c->used < n ? 64 - c->used : n;
        memcpy(c->buf + c->used, p, take);
        c->used += take; p += take; n -= take;
        if (c->used < 64)
            return;
        sha256_block(c->h, c->buf);
        c->used = 0;
    }
    for (; n >= 64; p += 64, n -= 64)
        sha256_block(c->h, p);
    memcpy(c->buf, p, n);
    c->used = n;
}

void erng_sha256_final(erng_sha256 *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80, zero = 0, lenbe[8];
    erng_sha256_update(c, &pad, 1);
    while (c->used != 56)
        erng_sha256_update(c, &zero, 1);
    for (int i = 0; i < 8; i++)
        lenbe[i] = (uint8_t)(bits >> (56 - 8 * i));
    erng_sha256_update(c, lenbe, 8);
    for (int i = 0; i < 8; i++) {
        out[4*i]   = (uint8_t)(c->h[i] >> 24);
        out[4*i+1] = (uint8_t)(c->h[i] >> 16);
        out[4*i+2] = (uint8_t)(c->h[i] >> 8);
        out[4*i+3] = (uint8_t)c->h[i];
    }
    wipe(c, sizeof *c);
}

/* HMAC over a list of message segments, so DRBG inputs need no concatenation buffer. */
typedef struct { const void *p; size_t n; } seg;

static void hmac_segs(const uint8_t *key, size_t keylen, const seg *s, int nseg, uint8_t out[32])
{
    uint8_t k[64] = {0}, pad[64], inner[32];
    erng_sha256 c;
    if (keylen > 64) {
        erng_sha256_init(&c);
        erng_sha256_update(&c, key, keylen);
        erng_sha256_final(&c, k);
    } else {
        memcpy(k, key, keylen);
    }
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    erng_sha256_init(&c);
    erng_sha256_update(&c, pad, 64);
    for (int i = 0; i < nseg; i++)
        if (s[i].n) erng_sha256_update(&c, s[i].p, s[i].n);
    erng_sha256_final(&c, inner);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    erng_sha256_init(&c);
    erng_sha256_update(&c, pad, 64);
    erng_sha256_update(&c, inner, 32);
    erng_sha256_final(&c, out);
    wipe(k, sizeof k); wipe(pad, sizeof pad); wipe(inner, sizeof inner);
}

void erng_hmac_sha256(const uint8_t *key, size_t keylen, const void *msg, size_t msglen, uint8_t out[32])
{
    seg s = { msg, msglen };
    hmac_segs(key, keylen, &s, 1, out);
}

/* ======================================================================== */
/* HMAC-DRBG (SP 800-90A Rev.1, 10.1.2)                                     */
/* ======================================================================== */

/* provided_data is the concatenation of up to 3 segments. */
static void drbg_update(erng_drbg *d, const seg *pd, int npd)
{
    static const uint8_t b0 = 0x00, b1 = 0x01;
    seg s[5] = { { d->V, 32 }, { &b0, 1 } };
    size_t total = 0;
    for (int i = 0; i < npd; i++) { s[2 + i] = pd[i]; total += pd[i].n; }

    hmac_segs(d->K, 32, s, 2 + npd, d->K);
    erng_hmac_sha256(d->K, 32, d->V, 32, d->V);
    if (total == 0)
        return;
    s[1].p = &b1;
    hmac_segs(d->K, 32, s, 2 + npd, d->K);
    erng_hmac_sha256(d->K, 32, d->V, 32, d->V);
}

void erng_drbg_instantiate(erng_drbg *d, const uint8_t *entropy, size_t elen,
                           const uint8_t *nonce, size_t nlen, const uint8_t *pers, size_t plen)
{
    seg pd[3] = { { entropy, elen }, { nonce, nlen }, { pers, plen } };
    memset(d->K, 0x00, 32);
    memset(d->V, 0x01, 32);
    drbg_update(d, pd, 3);
    d->reseed_counter = 1;
}

void erng_drbg_reseed(erng_drbg *d, const uint8_t *entropy, size_t elen, const uint8_t *add, size_t alen)
{
    seg pd[2] = { { entropy, elen }, { add, alen } };
    drbg_update(d, pd, 2);
    d->reseed_counter = 1;
}

int erng_drbg_generate(erng_drbg *d, uint8_t *out, size_t n, const uint8_t *add, size_t alen)
{
    seg pd = { add, alen };
    if (n > ERNG_DRBG_MAX_REQUEST)
        return ERNG_ERR_ARG;
    if (alen)
        drbg_update(d, &pd, 1);
    while (n) {
        size_t take = n < 32 ? n : 32;
        erng_hmac_sha256(d->K, 32, d->V, 32, d->V);
        memcpy(out, d->V, take);
        out += take; n -= take;
    }
    drbg_update(d, &pd, 1);
    d->reseed_counter++;
    return ERNG_OK;
}

/* ======================================================================== */
/* Health tests (SP 800-90B 4.4), false-positive rate 2^-30                 */
/* ======================================================================== */

void erng_health_init(erng_health *h, double H)
{
    double p = pow(2.0, -H);
    memset(h, 0, sizeof *h);
    h->rct_cutoff = 1 + (unsigned)ceil(30.0 / H);
    h->apt_window = 512;
    /* binomial critical value, normal approximation with a 6-sigma margin */
    h->apt_cutoff = (unsigned)ceil(512 * p + 6 * sqrt(512 * p * (1 - p))) + 1;
    h->rct_last = -1;
    h->apt_first = -1;
}

int erng_health_feed(erng_health *h, uint8_t s)
{
    if (s == h->rct_last) {
        if (++h->rct_run >= h->rct_cutoff)
            return -1;
    } else {
        h->rct_last = s;
        h->rct_run = 1;
    }
    if (h->apt_n == 0) {
        h->apt_first = s;
        h->apt_count = 1;
    } else if (s == h->apt_first && ++h->apt_count >= h->apt_cutoff) {
        return -1;
    }
    if (++h->apt_n == h->apt_window)
        h->apt_n = 0;
    return 0;
}

double erng_mcv_min_entropy(const uint8_t *s, size_t n)
{
    size_t cnt[256] = {0}, mx = 0;
    for (size_t i = 0; i < n; i++)
        if (++cnt[s[i]] > mx) mx = cnt[s[i]];
    double p = (double)mx / (double)n;
    double pu = p + 2.576 * sqrt(p * (1 - p) / (double)(n - 1));
    return -log2(pu > 1.0 ? 1.0 : pu);
}

/* ======================================================================== */
/* Entropy sources                                                          */
/* ======================================================================== */

/* Each source feeds its output straight into the pool hash and reports the
 * entropy it credits. A failing source returns an error and credits nothing. */

static int src_os(erng_sha256 *pool, size_t nbytes, double *credit)
{
    uint8_t buf[256];
    size_t done = 0;
    int rc = ERNG_ERR_ENTROPY;
    while (done < nbytes) {
        size_t want = nbytes - done < sizeof buf ? nbytes - done : sizeof buf;
        ssize_t r = getrandom(buf, want, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            goto out;
        }
        erng_sha256_update(pool, buf, (size_t)r);
        done += (size_t)r;
    }
    *credit = 8.0 * (double)nbytes;
    rc = ERNG_OK;
out:
    wipe(buf, sizeof buf);
    return rc;
}

static int hwrng_read(uint8_t *buf, size_t n)
{
    int fd = open(HWRNG_PATH, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    size_t done = 0;
    int tries = 0;
    if (fd < 0)
        return -1;
    while (done < n && tries < 200) {
        ssize_t r = read(fd, buf + done, n - done);
        if (r > 0) { done += (size_t)r; continue; }
        if (r < 0 && errno != EAGAIN && errno != EINTR) break;
        tries++;
        nanosleep(&(struct timespec){ 0, 1000000 }, NULL);   /* 1 ms */
    }
    close(fd);
    return done == n ? 0 : -1;
}

static int src_hwrng(erng_sha256 *pool, size_t nbytes, double *credit)
{
    uint8_t buf[256];
    size_t same = 1;
    int rc = ERNG_ERR_ENTROPY;
    if (nbytes > sizeof buf) nbytes = sizeof buf;
    if (hwrng_read(buf, nbytes) != 0)
        goto out;
    for (size_t i = 1; i < nbytes; i++) same += buf[i] == buf[0];
    if (nbytes > 4 && same == nbytes)
        goto out;                                /* stuck device */
    erng_sha256_update(pool, buf, nbytes);
    *credit = 4.0 * (double)nbytes;             /* half credit: hedge against a weak device */
    rc = ERNG_OK;
out:
    wipe(buf, sizeof buf);
    return rc;
}

#ifdef ERNG_X86
static int have_rdseed(void)
{
    unsigned a, b, c, d;
    return __get_cpuid_count(7, 0, &a, &b, &c, &d) && (b & (1u << 18));
}

static int rdseed64(uint64_t *v)
{
    for (int i = 0; i < 1000; i++) {
        unsigned char ok;
#if defined(__x86_64__)
        __asm__ volatile("rdseed %0; setc %1" : "=r"(*v), "=qm"(ok) :: "cc");
#else
        uint32_t lo = 0, hi = 0;
        __asm__ volatile("rdseed %0; setc %1" : "=r"(lo), "=qm"(ok) :: "cc");
        if (ok) __asm__ volatile("rdseed %0; setc %1" : "=r"(hi), "=qm"(ok) :: "cc");
        *v = (uint64_t)hi << 32 | lo;
#endif
        if (ok) return 0;
        __asm__ volatile("pause");
    }
    return -1;
}

static int src_rdseed(erng_sha256 *pool, size_t nbytes, double *credit)
{
    uint64_t v = 0, prev = 0;
    size_t words = (nbytes + 7) / 8;
    int rc = ERNG_ERR_ENTROPY;
    for (size_t i = 0; i < words; i++) {
        if (rdseed64(&v) != 0)
            goto out;
        /* known silicon bugs return all-zeros or all-ones; also catch a stuck value */
        if (v == 0 || v == UINT64_MAX || (i && v == prev))
            goto out;
        erng_sha256_update(pool, &v, sizeof v);
        prev = v;
    }
    *credit = 4.0 * (double)nbytes;             /* half credit: RDSEED cannot be audited */
    rc = ERNG_OK;
out:
    wipe(&v, sizeof v); wipe(&prev, sizeof prev);
    return rc;
}
#endif

/* ---- CPU jitter ---------------------------------------------------------- */

static inline uint64_t jitter_now(void)
{
#ifdef ERNG_X86
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)hi << 32 | lo;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
#endif
}

const char *erng_jitter_timer_name(void)
{
#ifdef ERNG_X86
    return "rdtsc";
#else
    return "clock_gettime";
#endif
}

uint8_t erng_jitter_sample(erng_jitter *j, int *stuck)
{
    /* Memory walk over a buffer larger than L1, with a loop count driven by the
     * previous timing so the workload itself varies. Timing differences come from
     * caches, TLB, branch prediction, interrupts and frequency scaling. */
    unsigned loops = 64 + (unsigned)(j->prev_delta & 63);
    uint32_t idx = j->idx;
    volatile uint8_t *m = j->mem;
    for (unsigned i = 0; i < loops; i++) {
        idx = (idx * 33u + 0x9E3779B9u + m[idx]) & (ERNG_JITTER_MEM - 1);
        m[idx] = (uint8_t)(m[idx] + 1);
    }
    j->idx = idx;

    uint64_t t = jitter_now();
    uint64_t delta = t - j->prev_t;
    uint64_t d2 = delta - j->prev_delta;
    uint64_t d3 = d2 - j->prev_d2;
    *stuck = delta == 0 || d2 == 0 || d3 == 0;
    j->prev_t = t;
    j->prev_delta = delta;
    j->prev_d2 = d2;
    return (uint8_t)delta;
}

int erng_jitter_init(erng_jitter *j)
{
    uint8_t *s;
    int stuck;
    memset(j, 0, sizeof *j);
    j->mem = calloc(ERNG_JITTER_MEM, 1);
    s = malloc(JITTER_STARTUP);
    if (!j->mem || !s) { free(s); erng_jitter_free(j); return ERNG_ERR_NOMEM; }

    j->prev_t = jitter_now();
    for (int i = 0; i < 64; i++)                 /* warm up caches and derivatives */
        erng_jitter_sample(j, &stuck);
    for (int i = 0; i < JITTER_STARTUP; i++)
        s[i] = erng_jitter_sample(j, &stuck);

    j->estimate = erng_mcv_min_entropy(s, JITTER_STARTUP);
    j->credit = j->estimate < JITTER_MAX_CREDIT ? j->estimate : JITTER_MAX_CREDIT;
    if (j->estimate < 0.1) {                     /* coarse or virtualised timer */
        wipe(s, JITTER_STARTUP); free(s); erng_jitter_free(j);
        return ERNG_ERR_ENTROPY;
    }
    erng_health_init(&j->health, j->credit);
    for (int i = 0; i < JITTER_STARTUP; i++)
        if (erng_health_feed(&j->health, s[i]) != 0) {
            wipe(s, JITTER_STARTUP); free(s); erng_jitter_free(j);
            return ERNG_ERR_ENTROPY;
        }
    wipe(s, JITTER_STARTUP);
    free(s);
    return ERNG_OK;
}

void erng_jitter_free(erng_jitter *j)
{
    free(j->mem);
    j->mem = NULL;
}

static int src_jitter(erng_jitter *j, erng_sha256 *pool, size_t nbytes, double *credit)
{
    double want = 8.0 * (double)nbytes, got = 0;
    size_t limit = (size_t)(64 * want / j->credit), n = 0;
    uint8_t block[64];
    size_t used = 0;
    int stuck;

    int rc = ERNG_ERR_ENTROPY;

    if (j->failed)
        return ERNG_ERR_ENTROPY;
    while (got < want) {
        if (++n > limit) { j->failed = 1; goto out; }   /* almost always stuck */
        uint8_t s = erng_jitter_sample(j, &stuck);
        if (erng_health_feed(&j->health, s) != 0) {
            j->failed = 1;                       /* permanent: a failed source stays out */
            goto out;
        }
        block[used++] = s;
        if (used == sizeof block) { erng_sha256_update(pool, block, used); used = 0; }
        if (!stuck) got += j->credit;
    }
    erng_sha256_update(pool, block, used);
    *credit = got;
    rc = ERNG_OK;
out:
    wipe(block, sizeof block);
    return rc;
}

/* ======================================================================== */
/* Generator                                                                */
/* ======================================================================== */

enum { SRC_OS, SRC_HWRNG, SRC_RDSEED, SRC_JITTER, SRC_COUNT };
static const char *const src_names[SRC_COUNT] = { "os", "hwrng", "rdseed", "jitter" };

struct erng {
    erng_drbg       drbg;           /* first: the secret state */
    pthread_mutex_t lock;
    unsigned        flags;
    int             has_os, has_hwrng, has_rdseed, has_jitter;
    erng_jitter     jitter;
    uint64_t        fork_gen;
    int64_t         clock_skew;     /* CLOCK_BOOTTIME - CLOCK_MONOTONIC at the last check, ns */
    unsigned long   failures[SRC_COUNT];
    struct erng    *prev, *next;    /* registry of live generators, for the fork handlers */
};

/* Fork handling. The prepare handler takes every generator's lock, so no thread
 * is inside a generator when fork() runs: the child never inherits a lock held
 * by a thread that no longer exists, nor a half-updated DRBG state. */
static atomic_uint_fast64_t g_fork_gen;
static pthread_once_t g_atfork_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_list_lock = PTHREAD_MUTEX_INITIALIZER;
static erng_t *g_list;

static void on_fork_prepare(void)
{
    pthread_mutex_lock(&g_list_lock);
    for (erng_t *r = g_list; r; r = r->next)
        pthread_mutex_lock(&r->lock);
}

static void on_fork_parent(void)
{
    for (erng_t *r = g_list; r; r = r->next)
        pthread_mutex_unlock(&r->lock);
    pthread_mutex_unlock(&g_list_lock);
}

static void on_fork_child(void)
{
    atomic_fetch_add(&g_fork_gen, 1);
    on_fork_parent();
}

static void register_atfork(void) { pthread_atfork(on_fork_prepare, on_fork_parent, on_fork_child); }

/* Suspend/resume (and, on hypervisors that account the gap as suspended time,
 * VM snapshot restore) moves CLOCK_BOOTTIME away from CLOCK_MONOTONIC. */
#define CLOCK_SKEW_RESEED_NS 1000000000LL

static int64_t clock_skew_now(void)
{
    struct timespec b, m;
    if (clock_gettime(CLOCK_BOOTTIME, &b) != 0 || clock_gettime(CLOCK_MONOTONIC, &m) != 0)
        return 0;
    return ((int64_t)b.tv_sec - (int64_t)m.tv_sec) * 1000000000LL + (b.tv_nsec - m.tv_nsec);
}

/* Gather from every source into a pool and emit a 64-byte seed.
 * Two SHA-256 digests with distinct prefixes over the same input (as in Hash_df).
 *
 * Credits are NOT summed. The seed is accepted only if one source on its own
 * credits the full target, so in practice the OS source or the jitter source.
 * hwrng and RDSEED (half credit) are mixed in as defence in depth but can never
 * carry the seed, alone or together: they may sit on the same silicon. */
static int gather(erng_t *r, size_t bits, uint8_t seed[64])
{
    erng_sha256 pool;
    double best = 0, c;
    size_t nbytes = (bits + 7) / 8;
    uint8_t ctr = 1;
    struct { uint64_t t; pid_t pid; } stamp;

    erng_sha256_init(&pool);
    erng_sha256_update(&pool, "entropy-rng/pool/v1", 19);

#define ADD(id, call) do { \
        erng_sha256_update(&pool, src_names[id], strlen(src_names[id]) + 1); \
        c = 0; \
        if ((call) == ERNG_OK) { if (c > best) best = c; } \
        else r->failures[id]++; } while (0)
    if (r->has_os)     ADD(SRC_OS, src_os(&pool, nbytes, &c));
    if (r->has_hwrng)  ADD(SRC_HWRNG, src_hwrng(&pool, nbytes, &c));
#ifdef ERNG_X86
    if (r->has_rdseed) ADD(SRC_RDSEED, src_rdseed(&pool, nbytes, &c));
#endif
    if (r->has_jitter) ADD(SRC_JITTER, src_jitter(&r->jitter, &pool, nbytes, &c));
#undef ADD
    stamp.t = jitter_now();
    stamp.pid = getpid();
    erng_sha256_update(&pool, &stamp, sizeof stamp);

    if (best < (double)bits) {
        wipe(&pool, sizeof pool);
        return ERNG_ERR_ENTROPY;
    }
    erng_sha256 c2 = pool;
    erng_sha256_update(&pool, &ctr, 1);
    erng_sha256_final(&pool, seed);
    ctr = 2;
    erng_sha256_update(&c2, &ctr, 1);
    erng_sha256_final(&c2, seed + 32);
    return ERNG_OK;
}

/* Reseed, and record that the state is now fresh for this process and clock. */
static int reseed_locked(erng_t *r, const void *add, size_t alen)
{
    uint8_t seed[64];
    uint64_t gen = atomic_load(&g_fork_gen);
    int rc = gather(r, SEED_ENTROPY_BITS, seed);
    if (rc == ERNG_OK) {
        erng_drbg_reseed(&r->drbg, seed, sizeof seed, add, alen);
        r->fork_gen = gen;
        r->clock_skew = clock_skew_now();
    }
    wipe(seed, sizeof seed);
    return rc;
}

int erng_new(erng_t **out, const void *pers, size_t perslen, unsigned flags)
{
    uint8_t seed[64];
    erng_t *r;
    int rc;

    if (!out || (perslen && !pers))
        return ERNG_ERR_ARG;
    pthread_once(&g_atfork_once, register_atfork);

    /* Private mapping: locked in RAM when allowed, excluded from core dumps. */
    r = mmap(NULL, sizeof *r, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (r == MAP_FAILED)
        return ERNG_ERR_NOMEM;
    (void)mlock(r, sizeof *r);
    (void)madvise(r, sizeof *r, MADV_DONTDUMP);

    memset(r, 0, sizeof *r);
    pthread_mutex_init(&r->lock, NULL);
    r->flags = flags;
    r->fork_gen = atomic_load(&g_fork_gen);
    r->clock_skew = clock_skew_now();
    r->has_os = !(flags & ERNG_NO_OS);
    if (!(flags & ERNG_NO_HWRNG)) {
        uint8_t b;
        r->has_hwrng = hwrng_read(&b, 1) == 0;
        wipe(&b, sizeof b);
    }
#ifdef ERNG_X86
    r->has_rdseed = !(flags & ERNG_NO_RDSEED) && have_rdseed();
#endif
    r->has_jitter = !(flags & ERNG_NO_JITTER) && erng_jitter_init(&r->jitter) == ERNG_OK;

    /* instantiate with 256 bits of entropy plus a 128-bit nonce */
    rc = gather(r, SEED_ENTROPY_BITS + SEED_ENTROPY_BITS / 2, seed);
    if (rc != ERNG_OK) {
        erng_free(r);
        return rc;
    }
    erng_drbg_instantiate(&r->drbg, seed, 48, seed + 48, 16, pers, perslen);
    wipe(seed, sizeof seed);

    pthread_mutex_lock(&g_list_lock);
    r->next = g_list;
    if (g_list) g_list->prev = r;
    g_list = r;
    pthread_mutex_unlock(&g_list_lock);
    *out = r;
    return ERNG_OK;
}

void erng_free(erng_t *r)
{
    if (!r) return;
    pthread_mutex_lock(&g_list_lock);
    if (r->prev) r->prev->next = r->next;
    else if (g_list == r) g_list = r->next;
    if (r->next) r->next->prev = r->prev;
    pthread_mutex_unlock(&g_list_lock);
    erng_jitter_free(&r->jitter);
    pthread_mutex_destroy(&r->lock);
    wipe(r, sizeof *r);
    munlock(r, sizeof *r);
    munmap(r, sizeof *r);
}

int erng_reseed(erng_t *r)
{
    int rc;
    if (!r) return ERNG_ERR_ARG;
    pthread_mutex_lock(&r->lock);
    rc = reseed_locked(r, NULL, 0);
    pthread_mutex_unlock(&r->lock);
    return rc;
}

int erng_bytes(erng_t *r, void *buf, size_t n)
{
    uint8_t *p = buf;
    int rc = ERNG_OK;
    int64_t skew;
    if (!r || (n && !buf)) return ERNG_ERR_ARG;

    pthread_mutex_lock(&r->lock);
    if (atomic_load(&g_fork_gen) != r->fork_gen) {
        /* we are a forked child: never continue the parent's stream */
        struct { char tag[4]; pid_t pid; } add = { "fork", getpid() };
        if ((rc = reseed_locked(r, &add, sizeof add)) != ERNG_OK) goto out;
    }
    skew = clock_skew_now() - r->clock_skew;
    if (skew > CLOCK_SKEW_RESEED_NS || skew < -CLOCK_SKEW_RESEED_NS) {
        /* resumed from suspend or a snapshot: the state may exist twice */
        static const char add[] = "resume";
        if ((rc = reseed_locked(r, add, sizeof add)) != ERNG_OK) goto out;
    }
    while (n) {
        size_t take = n < ERNG_DRBG_MAX_REQUEST ? n : ERNG_DRBG_MAX_REQUEST;
        if ((r->flags & ERNG_PREDICTION_RESISTANCE) || r->drbg.reseed_counter > RESEED_INTERVAL)
            if ((rc = reseed_locked(r, NULL, 0)) != ERNG_OK) goto out;
        erng_drbg_generate(&r->drbg, p, take, NULL, 0);
        p += take; n -= take;
    }
out:
    pthread_mutex_unlock(&r->lock);
    if (rc != ERNG_OK)
        wipe(buf, (size_t)(p - (uint8_t *)buf) + n);   /* never hand out partial output */
    return rc;
}

int erng_uniform(erng_t *r, uint64_t bound, uint64_t *out)
{
    uint64_t v, mask;
    int rc;
    if (!bound || !out) return ERNG_ERR_ARG;
    mask = bound - 1;
    mask |= mask >> 1; mask |= mask >> 2; mask |= mask >> 4;
    mask |= mask >> 8; mask |= mask >> 16; mask |= mask >> 32;
    do {                                          /* rejection sampling: < 2 tries on average */
        if ((rc = erng_bytes(r, &v, sizeof v)) != ERNG_OK) { wipe(&v, sizeof v); return rc; }
        v &= mask;
    } while (v >= bound);
    *out = v;
    wipe(&v, sizeof v);
    return ERNG_OK;
}

void erng_describe(const erng_t *r, char *buf, size_t len)
{
    int n = snprintf(buf, len, "sources:%s%s%s",
                     r->has_os ? " os" : "", r->has_hwrng ? " hwrng" : "",
                     r->has_rdseed ? " rdseed" : "");
    if (r->has_jitter && n >= 0 && (size_t)n < len)
        n += snprintf(buf + n, len - (size_t)n, " jitter(timer=%s, measured H=%.2f bits/sample, credited %.2f%s)",
                      erng_jitter_timer_name(), r->jitter.estimate, r->jitter.credit,
                      r->jitter.failed ? ", FAILED" : "");
    for (int i = 0; i < SRC_COUNT; i++)
        if (r->failures[i] && n >= 0 && (size_t)n < len)
            n += snprintf(buf + n, len - (size_t)n, " [%s failed %lu times]", src_names[i], r->failures[i]);
}

const char *erng_strerror(int err)
{
    switch (err) {
    case ERNG_OK:          return "ok";
    case ERNG_ERR_ENTROPY: return "insufficient entropy or source health test failure";
    case ERNG_ERR_ARG:     return "invalid argument";
    case ERNG_ERR_NOMEM:   return "out of memory";
    default:               return "unknown error";
    }
}

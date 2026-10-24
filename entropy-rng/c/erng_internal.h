/* Internal building blocks, exposed for the tests and the CLI's raw-sample dump. */
#ifndef ERNG_INTERNAL_H
#define ERNG_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

/* ---- SHA-256 / HMAC-SHA256 ---- */
typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    size_t   used;
} erng_sha256;

void erng_sha256_init(erng_sha256 *c);
void erng_sha256_update(erng_sha256 *c, const void *data, size_t n);
void erng_sha256_final(erng_sha256 *c, uint8_t out[32]);
void erng_hmac_sha256(const uint8_t *key, size_t keylen,
                      const void *msg, size_t msglen, uint8_t out[32]);

/* ---- HMAC-DRBG (SP 800-90A 10.1.2) ---- */
#define ERNG_DRBG_MAX_REQUEST 65536u

typedef struct {
    uint8_t  K[32];
    uint8_t  V[32];
    uint64_t reseed_counter;
} erng_drbg;

void erng_drbg_instantiate(erng_drbg *d, const uint8_t *entropy, size_t elen,
                           const uint8_t *nonce, size_t nlen,
                           const uint8_t *pers, size_t plen);
void erng_drbg_reseed(erng_drbg *d, const uint8_t *entropy, size_t elen,
                      const uint8_t *add, size_t alen);
int  erng_drbg_generate(erng_drbg *d, uint8_t *out, size_t n,
                        const uint8_t *add, size_t alen);

/* ---- Health tests (SP 800-90B 4.4) on 8-bit raw samples ---- */
typedef struct {
    unsigned rct_cutoff, apt_cutoff, apt_window;
    int      rct_last;
    unsigned rct_run;
    int      apt_first;
    unsigned apt_count, apt_n;
} erng_health;

void   erng_health_init(erng_health *h, double h_per_sample);
int    erng_health_feed(erng_health *h, uint8_t sample);   /* 0 ok, -1 failure */
double erng_mcv_min_entropy(const uint8_t *s, size_t n);   /* SP 800-90B 6.3.1 */

/* ---- Jitter source ---- */
#define ERNG_JITTER_MEM 65536u

typedef struct {
    uint8_t *mem;
    uint32_t idx;
    uint64_t prev_t, prev_delta, prev_d2;
    double   estimate;      /* measured min-entropy per sample */
    double   credit;        /* credited bits per sample (min(estimate, cap)) */
    erng_health health;
    int      failed;
} erng_jitter;

int  erng_jitter_init(erng_jitter *j);   /* measures entropy; ERNG_ERR_ENTROPY if too predictable */
void erng_jitter_free(erng_jitter *j);
/* One raw sample: low byte of the timing delta. *stuck is set if the first, second
 * or third derivative of the timing is zero (such samples get no credit). */
uint8_t erng_jitter_sample(erng_jitter *j, int *stuck);
const char *erng_jitter_timer_name(void);

#endif

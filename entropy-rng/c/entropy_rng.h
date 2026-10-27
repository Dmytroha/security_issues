/*
 * entropy_rng - entropy-based cryptographic random number generator (C prototype)
 *
 * Pipeline:
 *   entropy sources -> health tests -> SHA-256 pool (conditioning) -> HMAC-DRBG (SP 800-90A)
 *
 * Sources (all optional, used together when available):
 *   os      getrandom(2), kernel CSPRNG              credited 8 bits/byte
 *   hwrng   /dev/hwrng hardware RNG                  credited 4 bits/byte (defence in depth only)
 *   rdseed  x86 RDSEED instruction                   credited 4 bits/byte (defence in depth only)
 *   jitter  CPU execution-time jitter (rdtsc)        measured at start-up, credited <= 1 bit/sample
 *
 * Credits are not summed: a seed needs one source (in practice os or jitter) to
 * credit the full target on its own. Failed sources are counted in erng_describe().
 *
 * An erng_t is thread-safe and reseeds itself after fork() and after suspend/resume.
 * A VM snapshot/restore or clone copies its state: use ERNG_PREDICTION_RESISTANCE
 * for keys so every request draws fresh entropy.
 */
#ifndef ENTROPY_RNG_H
#define ENTROPY_RNG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct erng erng_t;

/* Flags for erng_new() */
#define ERNG_PREDICTION_RESISTANCE 0x01u /* reseed from the sources before every request */
#define ERNG_NO_OS                 0x02u /* disable individual sources (mainly for testing) */
#define ERNG_NO_HWRNG              0x04u
#define ERNG_NO_RDSEED             0x08u
#define ERNG_NO_JITTER             0x10u

/* Return codes */
#define ERNG_OK           0
#define ERNG_ERR_ENTROPY (-1) /* sources failed health tests or delivered too little entropy */
#define ERNG_ERR_ARG     (-2)
#define ERNG_ERR_NOMEM   (-3)

int  erng_new(erng_t **out, const void *personalization, size_t perslen, unsigned flags);
void erng_free(erng_t *rng);

/* Fill buf with n random bytes. */
int  erng_bytes(erng_t *rng, void *buf, size_t n);

/* Uniform integer in [0, bound), no modulo bias. bound must be > 0. */
int  erng_uniform(erng_t *rng, uint64_t bound, uint64_t *out);

/* Force a reseed from the entropy sources. */
int  erng_reseed(erng_t *rng);

/* Human-readable list of active sources and the jitter entropy estimate. */
void erng_describe(const erng_t *rng, char *buf, size_t len);

const char *erng_strerror(int err);

#ifdef __cplusplus
}
#endif
#endif

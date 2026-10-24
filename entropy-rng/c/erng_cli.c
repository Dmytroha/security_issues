/* erng - command-line front end for entropy_rng */
#define _GNU_SOURCE
#include "entropy_rng.h"
#include "erng_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void)
{
    fprintf(stderr,
        "usage: erng [-n BYTES] [--raw] [--stream] [--pr] [-v]\n"
        "       erng --jitter-raw SAMPLES   raw 8-bit jitter samples (for NIST SP 800-90B tools)\n"
        "  -n BYTES   output BYTES random bytes (default 32), hex unless --raw\n"
        "  --raw      write raw bytes\n"
        "  --stream   write raw bytes until the pipe closes (for dieharder, PractRand, ent)\n"
        "  --pr       prediction resistance (reseed before every request)\n"
        "  -v         print active sources to stderr\n");
    exit(2);
}

static int write_all(const void *p, size_t n)
{
    const char *c = p;
    while (n) {
        ssize_t w = write(STDOUT_FILENO, c, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        c += w; n -= (size_t)w;
    }
    return 0;
}

int main(int argc, char **argv)
{
    size_t n = 32, jitter_raw = 0;
    int raw = 0, stream = 0, verbose = 0, rc;
    unsigned flags = 0;
    static unsigned char buf[65536];

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-n") && i + 1 < argc) n = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--raw")) raw = 1;
        else if (!strcmp(argv[i], "--stream")) stream = 1;
        else if (!strcmp(argv[i], "--pr")) flags |= ERNG_PREDICTION_RESISTANCE;
        else if (!strcmp(argv[i], "-v")) verbose = 1;
        else if (!strcmp(argv[i], "--jitter-raw") && i + 1 < argc) jitter_raw = strtoull(argv[++i], NULL, 0);
        else usage();
    }

    if (jitter_raw) {
        erng_jitter j;
        int stuck;
        if ((rc = erng_jitter_init(&j)) != ERNG_OK) {
            fprintf(stderr, "erng: jitter source unusable: %s\n", erng_strerror(rc));
            return 1;
        }
        fprintf(stderr, "timer=%s start-up MCV estimate H=%.3f bits/sample\n",
                erng_jitter_timer_name(), j.estimate);
        while (jitter_raw) {
            size_t k = jitter_raw < sizeof buf ? jitter_raw : sizeof buf;
            for (size_t i = 0; i < k; i++) buf[i] = erng_jitter_sample(&j, &stuck);
            if (write_all(buf, k)) break;
            jitter_raw -= k;
        }
        erng_jitter_free(&j);
        return 0;
    }

    erng_t *rng;
    if ((rc = erng_new(&rng, "erng-cli", 8, flags)) != ERNG_OK) {
        fprintf(stderr, "erng: %s\n", erng_strerror(rc));
        return 1;
    }
    if (verbose) {
        char d[256];
        erng_describe(rng, d, sizeof d);
        fprintf(stderr, "%s\n", d);
    }
    if (stream) {
        while ((rc = erng_bytes(rng, buf, sizeof buf)) == ERNG_OK && write_all(buf, sizeof buf) == 0)
            ;
    } else {
        while (n) {
            size_t k = n < sizeof buf ? n : sizeof buf;
            if ((rc = erng_bytes(rng, buf, k)) != ERNG_OK) break;
            if (raw) write_all(buf, k);
            else for (size_t i = 0; i < k; i++) printf("%02x", buf[i]);
            n -= k;
        }
        if (!raw) printf("\n");
    }
    if (rc != ERNG_OK) fprintf(stderr, "erng: %s\n", erng_strerror(rc));
    erng_free(rng);
    return rc == ERNG_OK ? 0 : 1;
}

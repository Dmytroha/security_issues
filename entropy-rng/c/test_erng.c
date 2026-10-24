/* Tests for entropy_rng: known-answer vectors, health tests, statistics, fork and threads. */
#define _GNU_SOURCE
#include "entropy_rng.h"
#include "erng_internal.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static void unhex(const char *h, uint8_t *out)
{
    for (size_t i = 0; h[2*i]; i++) sscanf(h + 2*i, "%2hhx", &out[i]);
}

static int eqhex(const uint8_t *b, size_t n, const char *h)
{
    uint8_t x[256];
    unhex(h, x);
    return strlen(h) == 2 * n && memcmp(b, x, n) == 0;
}

static void test_sha256(void)
{
    erng_sha256 c;
    uint8_t d[32];
    erng_sha256_init(&c); erng_sha256_final(&c, d);
    CHECK(eqhex(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    erng_sha256_init(&c); erng_sha256_update(&c, "abc", 3); erng_sha256_final(&c, d);
    CHECK(eqhex(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    erng_sha256_init(&c); erng_sha256_update(&c, m, strlen(m)); erng_sha256_final(&c, d);
    CHECK(eqhex(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    /* one million 'a', fed in odd-sized chunks to exercise buffering */
    char a[997]; memset(a, 'a', sizeof a);
    erng_sha256_init(&c);
    for (size_t left = 1000000; left; ) { size_t k = left < sizeof a ? left : sizeof a; erng_sha256_update(&c, a, k); left -= k; }
    erng_sha256_final(&c, d);
    CHECK(eqhex(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

static void test_hmac(void)
{
    uint8_t k[131], d[32];
    memset(k, 0x0b, 20);   /* RFC 4231 test case 1 */
    erng_hmac_sha256(k, 20, "Hi There", 8, d);
    CHECK(eqhex(d, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    erng_hmac_sha256((const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28, d);   /* case 2 */
    CHECK(eqhex(d, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    memset(k, 0xaa, 131);  /* case 6: key longer than block size */
    const char *m = "Test Using Larger Than Block-Size Key - Hash Key First";
    erng_hmac_sha256(k, 131, m, strlen(m), d);
    CHECK(eqhex(d, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
}

static void test_drbg_cavp(void)
{
    /* NIST CAVP HMAC_DRBG.rsp [SHA-256] PredictionResistance=False, COUNT=0 */
    uint8_t e[32], n[16], out[128];
    erng_drbg d;
    unhex("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488", e);
    unhex("659ba96c601dc69fc902940805ec0ca8", n);
    erng_drbg_instantiate(&d, e, 32, n, 16, NULL, 0);
    erng_drbg_generate(&d, out, 128, NULL, 0);
    erng_drbg_generate(&d, out, 128, NULL, 0);
    CHECK(eqhex(out, 128,
        "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89"
        "d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1"
        "07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668"
        "961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8"));
    CHECK(erng_drbg_generate(&d, out, ERNG_DRBG_MAX_REQUEST + 1, NULL, 0) == ERNG_ERR_ARG);
}

static int feed_all(erng_health *h, const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++) if (erng_health_feed(h, s[i])) return -1;
    return 0;
}

static void test_health(void)
{
    erng_health h;
    uint8_t s[4096];
    memset(s, 7, sizeof s);
    erng_health_init(&h, 1.0);
    CHECK(feed_all(&h, s, 100) == -1);           /* stuck source -> RCT */
    for (size_t i = 0; i < sizeof s; i++) s[i] = (uint8_t)(i & 1 ? 6 : 5);
    erng_health_init(&h, 2.0);                   /* claims p_max = 1/4, value 5 is 1/2 */
    CHECK(feed_all(&h, s, sizeof s) == -1);
    erng_t *r;
    CHECK(erng_new(&r, NULL, 0, ERNG_NO_JITTER) == ERNG_OK);
    erng_bytes(r, s, sizeof s);
    erng_health_init(&h, 1.0);
    CHECK(feed_all(&h, s, sizeof s) == 0);       /* good data passes */
    erng_free(r);
}

static void test_sources(void)
{
    erng_t *r;
    char d[256];
    uint8_t a[32], b[32];
    /* each hardware-ish source must be able to seed on its own where present */
    CHECK(erng_new(&r, NULL, 0, ERNG_NO_OS | ERNG_NO_HWRNG | ERNG_NO_RDSEED) == ERNG_OK);
    erng_describe(r, d, sizeof d);
    printf("  jitter only: %s\n", d);
    CHECK(strstr(d, "jitter") && !strstr(d, " os"));
    CHECK(erng_bytes(r, a, 32) == ERNG_OK);
    erng_free(r);
    /* with everything disabled, seeding must fail loudly */
    CHECK(erng_new(&r, NULL, 0, ERNG_NO_OS | ERNG_NO_HWRNG | ERNG_NO_RDSEED | ERNG_NO_JITTER) == ERNG_ERR_ENTROPY);
    /* two instances never agree */
    erng_t *r1 = NULL, *r2 = NULL;
    CHECK(erng_new(&r1, NULL, 0, 0) == ERNG_OK && erng_new(&r2, NULL, 0, 0) == ERNG_OK);
    erng_describe(r1, d, sizeof d);
    printf("  default: %s\n", d);
    erng_bytes(r1, a, 32); erng_bytes(r2, b, 32);
    CHECK(memcmp(a, b, 32) != 0);
    CHECK(erng_reseed(r1) == ERNG_OK);
    erng_free(r1); erng_free(r2);
    CHECK(erng_new(&r, NULL, 0, ERNG_PREDICTION_RESISTANCE) == ERNG_OK);
    CHECK(erng_bytes(r, a, 32) == ERNG_OK);
    erng_free(r);
}

static void test_statistics(void)
{
    erng_t *r;
    size_t n = 1 << 22;
    uint8_t *buf = malloc(n);
    unsigned long cnt[256] = {0}, ones = 0;
    CHECK(erng_new(&r, NULL, 0, 0) == ERNG_OK);
    CHECK(erng_bytes(r, buf, n) == ERNG_OK);    /* > 64 KiB: crosses request chunks */
    for (size_t i = 0; i < n; i++) { cnt[buf[i]]++; ones += (unsigned long)__builtin_popcount(buf[i]); }
    double exp = n / 256.0, chi2 = 0;
    for (int i = 0; i < 256; i++) chi2 += (cnt[i] - exp) * (cnt[i] - exp) / exp;
    double z = ((double)ones - 4.0 * n) / sqrt(2.0 * n);
    printf("  4 MiB: chi2=%.1f (df=255), monobit z=%.2f\n", chi2, z);
    CHECK(chi2 < 340 && chi2 > 180);
    CHECK(fabs(z) < 4.5);

    unsigned long faces[6] = {0};
    for (int i = 0; i < 60000; i++) { uint64_t v; erng_uniform(r, 6, &v); CHECK(v < 6); faces[v]++; }
    for (int i = 0; i < 6; i++) CHECK(faces[i] > 9500 && faces[i] < 10500);
    uint64_t v;
    CHECK(erng_uniform(r, 0, &v) == ERNG_ERR_ARG);
    CHECK(erng_uniform(r, 1, &v) == ERNG_OK && v == 0);
    erng_free(r);
    free(buf);
}

static void test_fork(void)
{
    erng_t *r;
    uint8_t mine[32], child[32];
    int fd[2];
    CHECK(erng_new(&r, NULL, 0, 0) == ERNG_OK);
    erng_bytes(r, mine, 16);
    CHECK(pipe(fd) == 0);
    pid_t pid = fork();
    if (pid == 0) {
        erng_bytes(r, child, 32);
        _exit(write(fd[1], child, 32) == 32 ? 0 : 1);
    }
    waitpid(pid, NULL, 0);
    CHECK(read(fd[0], child, 32) == 32);
    erng_bytes(r, mine, 32);
    CHECK(memcmp(mine, child, 32) != 0);
    close(fd[0]); close(fd[1]);
    erng_free(r);
}

static erng_t *shared;
static uint8_t thread_out[8][4096];
static void *worker(void *arg)
{
    uint8_t *o = arg;
    for (int i = 0; i < 64; i++) erng_bytes(shared, o + (i % 64) * 64, 64);
    return NULL;
}

static void test_threads(void)
{
    pthread_t t[8];
    CHECK(erng_new(&shared, NULL, 0, 0) == ERNG_OK);
    for (int i = 0; i < 8; i++) pthread_create(&t[i], NULL, worker, thread_out[i]);
    for (int i = 0; i < 8; i++) pthread_join(t[i], NULL);
    for (int i = 0; i < 8; i++)
        for (int j = i + 1; j < 8; j++)
            CHECK(memcmp(thread_out[i], thread_out[j], 4096) != 0);
    erng_free(shared);
}

int main(void)
{
    test_sha256();
    test_hmac();
    test_drbg_cavp();
    test_health();
    test_sources();
    test_statistics();
    test_fork();
    test_threads();
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}

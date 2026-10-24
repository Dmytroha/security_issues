# entropy_rng in C

The C port of the Python prototype one folder up. Linux, C11, no dependencies beyond libc, libm and pthreads.

```
make              # builds liberng.a, the erng CLI and test_erng
make check        # run the tests
make asan         # tests under AddressSanitizer + UndefinedBehaviorSanitizer

./erng -v -n 32                         # 32 bytes as hex, active sources on stderr
./erng --stream | RNG_test stdin8       # endless stream for PractRand / dieharder / ent
./erng --jitter-raw 1000000 > jit.bin   # raw jitter samples for NIST SP 800-90B tools
```

> `/mnt/project-files` is mounted `noexec`, so copy the folder somewhere else before running `make`.

```c
#include "entropy_rng.h"

erng_t *rng;
if (erng_new(&rng, "my-app", 6, 0) != ERNG_OK) abort();
uint8_t key[32];
erng_bytes(rng, key, sizeof key);
uint64_t die;
erng_uniform(rng, 6, &die);             /* 0..5, no modulo bias */
erng_free(rng);
```

## What the C version does

```
 getrandom(2) ───┐  8 bits/byte credited
 /dev/hwrng ─────┤  4 bits/byte (hedge against weak hardware)
 RDSEED (x86) ───┤  4 bits/byte (hedge: cannot be audited)
 CPU jitter ─────┘  measured at start-up, ≤ 1 bit/sample
        │
        ▼  SP 800-90B health tests (repetition count, adaptive proportion) + stuck test
   SHA-256 pool  ──►  64-byte seed  ──►  HMAC-DRBG-SHA256 (SP 800-90A)  ──►  output
```

Compared to the Python version:

- **RDSEED** added as a hardware noise source, with checks for the known silicon bugs (all-zeros, all-ones, repeated values).
- **Jitter** uses `rdtsc` (cycle counter) on x86 and `clock_gettime(CLOCK_MONOTONIC_RAW)` elsewhere. The workload is a memory walk over 64 KiB, larger than L1 cache, and its length depends on the previous timing. As in Linux's jitterentropy, samples whose first, second or third timing derivative is zero are hashed but get no credit. A source that fails a health test is switched off for good.
- **Every source feeds every gather**, so the seed is strong as long as any one of them is good. Seeding fails with `ERNG_ERR_ENTROPY` if the credited total is short, and no partial output is ever returned.
- **Memory hygiene**: the generator state sits in its own `mmap` region, `mlock`ed (when allowed) and excluded from core dumps. All secrets are cleared with `explicit_bzero`.
- **Fork safety**: a `pthread_atfork` hook bumps a generation counter, and a child reseeds before its first output, so parent and child never share a stream. **Thread safety**: one mutex per generator.
- **Reseeding** happens every 65 536 requests, on `erng_reseed()`, or before every request with `ERNG_PREDICTION_RESISTANCE`.

## Verification

- Known-answer tests: SHA-256 (FIPS 180-2 vectors including one million 'a'), HMAC-SHA256 (RFC 4231 cases 1, 2 and 6), HMAC-DRBG (NIST CAVP vector).
- Health tests reject a stuck source and a biased source, and accept good data.
- Jitter on its own can seed the generator. With every source disabled, seeding fails.
- 4 MiB output: byte chi-square and monobit tests pass. `erng_uniform` is uniform.
- After a fork the child's output differs from the parent's. 8 threads sharing one generator get distinct output.
- Builds with no warnings under gcc and clang with `-Wall -Wextra -Wpedantic -Wshadow`, and runs clean under ASan + UBSan.
- **PractRand**: 8 GB of output, no anomalies in any of 159 test results.

Throughput is about 16 MB/s with the portable SHA-256. Using SHA-NI or OpenSSL would speed this up by several times.

## Measured jitter entropy (this cloud VM)

The start-up Most Common Value estimate comes out at about 6.4 bits/sample, and LZMA compresses the raw samples to about 7.1 bits/sample. Both overestimate, because timing samples are not independent. That is why the credit is capped at 1 bit/sample. For a defensible figure, run the NIST non-IID suite (`ea_non_iid`) on `erng --jitter-raw` output from the target hardware.

## Known limits

- Research prototype, not audited. In production, use `getrandom(2)`, which is built the same way inside the kernel.
- If one thread forks while another holds the generator's mutex, the child can deadlock. This is the usual limitation of pthread-based libraries.
- Inside a VM the hypervisor can trap or emulate `rdtsc`, so jitter quality depends on the host. The start-up estimate disables the source if the timer turns out to be coarse.

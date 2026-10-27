# entropy_rng in C

The C port of the Python prototype one folder up. Linux, C11, no dependencies beyond libc, libm and pthreads.

```
make              # builds liberng.a, the erng CLI and test_erng
make check        # run the tests
make asan         # tests under AddressSanitizer + UndefinedBehaviorSanitizer

./erng -v -n 32                         # 32 bytes as hex, active sources on stderr
./erng --stream | RNG_test stdin8       # endless stream for PractRand / dieharder / ent (sanity only)
./erng --jitter-raw 1000000 > jit.bin   # raw jitter samples for NIST SP 800-90B tools
```

> `/mnt/project-files` is mounted `noexec`, so copy the folder somewhere else before running `make`.

```c
#include "entropy_rng.h"

erng_t *rng;
/* ERNG_PREDICTION_RESISTANCE: fresh entropy for every request; use it for keys */
if (erng_new(&rng, "my-app", 6, ERNG_PREDICTION_RESISTANCE) != ERNG_OK) abort();
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
- **Every source feeds every gather**, so the seed is strong as long as any one of them is good. Credits are **not summed**: a seed is accepted only if one source on its own credits the full target (256 bits per reseed, 384 at instantiation). In practice that is `getrandom` or the jitter source. hwrng and RDSEED are half-credited, so they are defence in depth only and can never carry the seed, alone or together (they may sit on the same silicon, e.g. RDRAND-backed virtio-rng). Seeding fails with `ERNG_ERR_ENTROPY` otherwise, and no partial output is ever returned.
- **Failed sources are counted**: a read error, a stuck device or a health-test failure skips that source for the gather and increments a per-source counter shown by `erng_describe` (and `erng -v`).
- **Security level in practice**: when `getrandom` works it meets the threshold by itself, so the output is as strong as the kernel CSPRNG and the health tests do not gate seeding. They decide only when jitter is the sole full-credit source.
- **Memory hygiene**: the generator state sits in its own `mmap` region, `mlock`ed (when allowed) and excluded from core dumps. All secrets, including stack buffers on error paths, are cleared with `explicit_bzero`.
- **Fork safety**: `pthread_atfork` handlers take every generator's lock before `fork()` and release it in both processes, so a fork while another thread is generating cannot deadlock the child or hand it a half-updated state. The child handler also bumps a generation counter, and a child reseeds before its first output, so parent and child never share a stream. **Thread safety**: one mutex per generator.
- **Reseeding** happens every 65 536 requests, on `erng_reseed()`, when `CLOCK_BOOTTIME` and `CLOCK_MONOTONIC` drift apart by more than a second (suspend/resume), or before every request with `ERNG_PREDICTION_RESISTANCE`.

## Verification

### Correctness tests

- Known-answer tests: SHA-256 (FIPS 180-2 vectors including one million 'a'), HMAC-SHA256 (RFC 4231 cases 1, 2 and 6), HMAC-DRBG (NIST CAVP vector).
- Health tests reject a stuck source and a biased source, and accept good data.
- Jitter on its own can seed the generator, also with `ERNG_NO_OS`. hwrng plus RDSEED without a full-credit source cannot. With every source disabled, seeding fails.
- After a fork the child's output differs from the parent's. Forking while another thread holds the generator does not deadlock the child. 8 threads sharing one generator get distinct output.
- Builds with no warnings under gcc and clang with `-Wall -Wextra -Wpedantic -Wshadow`, and runs clean under ASan + UBSan.

### Entropy source assessment (the actual evidence)

Only an SP 800-90B assessment of the **raw** jitter samples says anything about the quality of the jitter source. Run it on the target hardware and record the result per platform:

```
./erng --jitter-raw 1000000 > jit.bin
ea_non_iid -v jit.bin 8                 # from github.com/usnistgov/SP800-90B_EntropyAssessment
```

| Platform | Timer | `ea_non_iid` min-entropy (bits/sample) | Date |
|---|---|---|---|
| _not yet measured_ | | | |

The other sources are not assessed here: `getrandom` is the kernel's responsibility, and hwrng / RDSEED cannot be audited from user space (hence half credit).

### Statistical sanity checks (do not demonstrate cryptographic strength)

- 4 MiB output: byte chi-square and monobit tests pass. `erng_uniform` is uniform.
- PractRand: 8 GB of output, no anomalies in any of 159 test results.

These only show that the DRBG and the output plumbing are not grossly broken. HMAC-DRBG output passes every statistical suite even when seeded with a constant, so they say **nothing** about the entropy sources or about whether the output is unpredictable.

Throughput is about 16 MB/s with the portable SHA-256. Using SHA-NI or OpenSSL would speed this up by several times.

## Measured jitter entropy (this cloud VM)

The start-up Most Common Value estimate comes out at about 6.4 bits/sample, and LZMA compresses the raw samples to about 7.1 bits/sample. Both overestimate, because timing samples are not independent. That is why the credit is capped at 1 bit/sample. For a defensible figure, run the NIST non-IID suite (`ea_non_iid`) on `erng --jitter-raw` output from the target hardware.

## Known limits

- Research prototype, not audited. In production, use `getrandom(2)`, which is built the same way inside the kernel.
- **VM snapshot/restore, VM cloning, CRIU checkpoints**: these copy the DRBG state without a `fork()`, so two copies would emit the **same** next bytes. The kernel handles this through vmgenid, but Linux does not expose a vmgenid change to user space. The `CLOCK_BOOTTIME` drift check catches suspend/resume and restores that the guest kernel accounts as suspended time, which is not guaranteed. For keys, use `ERNG_PREDICTION_RESISTANCE`: every request then reseeds from `getrandom`, which the kernel reseeds on a vmgenid change.
- Inside a VM the hypervisor can trap or emulate `rdtsc`, so jitter quality depends on the host. The start-up estimate disables the source if the timer turns out to be coarse.

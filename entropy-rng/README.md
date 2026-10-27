# Entropy-based random generator (prototype)

Pure Python 3, no dependencies. `entropy_rng.py` is the generator, `test_entropy_rng.py` the tests.

```
python3 entropy_rng.py -n 32          # 32 random bytes as hex, sources listed on stderr
python3 entropy_rng.py --stream | ent  # endless raw stream for ent / dieharder / PractRand
python3 -m unittest -v test_entropy_rng
```

```python
from entropy_rng import EntropyRNG
with EntropyRNG() as rng:          # close() overwrites the DRBG state on exit
    die = rng.randint(1, 6)
    nonce = rng.random_bytes(16)
# for real keys use secrets.token_bytes(32) or the C version (see "Honest limits")
```

## Design

```
 OS CSPRNG (getrandom) ─┐
 /dev/hwrng (hardware) ─┼─► health tests ─► SHA-512 pool ─► HMAC-DRBG-SHA256 ─► output
 CPU timing jitter ─────┘                   (conditioning)   (SP 800-90A)
```

1. **Entropy sources**
   - `OSSource`: the kernel CSPRNG via `os.urandom`. Credited 8 bits/byte.
   - `HWRNGSource`: `/dev/hwrng` if readable (TPM, RDRAND-backed virtio-rng, etc.). Credited only 4 bits/byte as a hedge against a weak or backdoored device.
   - `JitterSource`: times a small memory-walking workload with a nanosecond clock and keeps the low byte of each delta. Cache, TLB, branch predictor, interrupt and frequency-scaling effects make it noisy. At start-up it measures min-entropy with the SP 800-90B Most Common Value estimator and credits at most 1 bit per sample, however good it looks.
2. **Health tests** (SP 800-90B §4.4) run continuously on raw jitter samples: the Repetition Count Test catches a stuck source, the Adaptive Proportion Test catches one that has become biased. A source that fails (health test, `EntropyError` or `OSError` such as a vanished device) is dropped from that gather and counted in `rng.pool.failures`, which `describe()` also prints.
3. **Pool**: every source contributes to a SHA-512 hash on every gather, so the seed is strong as long as any one source is good. Credits are **not summed**: seeding fails loudly unless one source on its own credits the target (384 bits at instantiation = 256 entropy + nonce, 256 per reseed), and no source can credit more than 8 bits per byte it returned. In practice the OS source or the jitter source carries the seed. hwrng is half-credited and only adds defence in depth. When `os.urandom` works, the output is as strong as the kernel CSPRNG.
4. **DRBG**: HMAC-DRBG with SHA-256, verified against the NIST CAVP test vector. It reseeds automatically every 65 536 requests, after `fork()` (so parent and child never share output), when `CLOCK_BOOTTIME` and `CLOCK_MONOTONIC` drift apart by more than a second (suspend/resume), and optionally before every request (`prediction_resistance=True`).
5. **Helpers**: `randbelow` / `randint` use rejection sampling (no modulo bias); `random()` gives 53-bit floats.

## Honest limits

- This is a research prototype, not an audited library. For production use `secrets` / `os.urandom`, which the kernel already builds the same way.
- Python timing loops are slow and dominated by interpreter noise, which inflates the jitter estimate (measured ~6.4 bits/sample here, credited 1). A C implementation would make the jitter source meaningful on its own.
- **Not suitable for key material.** `random_bytes()` returns immutable `bytes`, which cannot be zeroed after use, and Python cannot reliably erase secrets: intermediate copies made by `hmac`/`hashlib` linger in freed objects. `close()` overwrites the DRBG's `K` and `V` buffers, but that is best effort. For real keys use `secrets.token_bytes(32)` or the C version.
- **VM snapshot/restore, VM cloning, CRIU checkpoints** copy the DRBG state without a `fork()`, so both copies emit the **same** next output (`test_snapshot_clone_default_mode_repeats` shows this). The clock-drift check only catches restores the guest kernel accounts as suspended time. Use `prediction_resistance=True` when output must stay unique: every request then reseeds from `os.urandom`, which the kernel reseeds on a vmgenid change.
- Statistical tests (chi-square, monobit, PractRand) only show the output plumbing is not grossly broken. A DRBG seeded with a constant passes them too, so they prove nothing about the entropy sources.

## C version

See [c/README.md](c/README.md): adds RDSEED, rdtsc-based jitter, locked memory, fork/thread safety and `explicit_bzero` of every secret, plus how to assess the jitter source with the NIST SP 800-90B tools.

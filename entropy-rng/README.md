# Entropy-based random generator (prototype)

Pure Python 3, no dependencies. `entropy_rng.py` is the generator, `test_entropy_rng.py` the tests.

```
python3 entropy_rng.py -n 32          # 32 random bytes as hex, sources listed on stderr
python3 entropy_rng.py --stream | ent  # endless raw stream for ent / dieharder / PractRand
python3 -m unittest -v test_entropy_rng
```

```python
from entropy_rng import EntropyRNG
rng = EntropyRNG()                 # or EntropyRNG(prediction_resistance=True)
key = rng.random_bytes(32)
die = rng.randint(1, 6)
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
2. **Health tests** (SP 800-90B §4.4) run continuously on raw jitter samples: the Repetition Count Test catches a stuck source, the Adaptive Proportion Test catches one that has become biased. A failing source is dropped from that gather.
3. **Pool**: every source contributes to a SHA-512 hash on every gather, so the seed is strong as long as any one source is good. Seeding fails loudly if the credited total is below the target (384 bits at instantiation = 256 entropy + nonce, 256 per reseed).
4. **DRBG**: HMAC-DRBG with SHA-256, verified against the NIST CAVP test vector. It reseeds automatically every 65 536 requests, after `fork()` (so parent and child never share output), and optionally before every request (`prediction_resistance=True`).
5. **Helpers**: `randbelow` / `randint` use rejection sampling (no modulo bias); `random()` gives 53-bit floats.

## Honest limits

- This is a research prototype, not an audited library. For production use `secrets` / `os.urandom`, which the kernel already builds the same way.
- Python timing loops are slow and dominated by interpreter noise, which inflates the jitter estimate (measured ~6.4 bits/sample here, credited 1). A C implementation would make the jitter source meaningful on its own.
- Python cannot reliably erase secrets from memory; state may linger in freed objects.

## C version

See [c/README.md](c/README.md): adds RDSEED, rdtsc-based jitter, locked memory and fork/thread safety, and passes 8 GB of PractRand.

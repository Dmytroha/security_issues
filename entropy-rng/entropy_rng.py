"""Entropy-based cryptographic random number generator (prototype).

Pipeline:
    entropy sources -> health tests -> SHA-512 pool (conditioning) -> HMAC-DRBG (SP 800-90A)

Sources:
    * OSSource      - kernel CSPRNG via os.urandom / getrandom(2)
    * HWRNGSource   - /dev/hwrng hardware RNG, if present and readable
    * JitterSource  - CPU timing jitter (in the spirit of Linux jitterentropy)

The DRBG is seeded only once a single source on its own credits at least
SEED_ENTROPY_BITS; credits are never summed across sources. Raw jitter samples
pass continuous health tests (SP 800-90B repetition count + adaptive
proportion) before they are credited.

Python cannot reliably erase memory: random_bytes() returns immutable bytes and
interpreter copies may linger. For real keys use secrets.token_bytes() or the C
version in c/.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import math
import os
import threading
import time
import weakref

SEED_ENTROPY_BITS = 256          # security strength of HMAC-DRBG-SHA256
RESEED_INTERVAL = 1 << 16        # generate() calls between automatic reseeds
MAX_REQUEST_BYTES = 1 << 16      # SP 800-90A limit is 2^19 bits per request


class EntropyError(RuntimeError):
    """A source failed its health tests or could not deliver entropy."""


# --------------------------------------------------------------------------- #
# Health tests (NIST SP 800-90B, section 4.4)
# --------------------------------------------------------------------------- #

class HealthTests:
    """Continuous tests on raw 8-bit samples, parameterised by the claimed
    min-entropy per sample H and a false-positive rate of 2^-30."""

    def __init__(self, h_per_sample: float, window: int = 512):
        self.h = h_per_sample
        # Repetition Count Test cutoff: 1 + ceil(30 / H)
        self.rct_cutoff = 1 + math.ceil(30 / h_per_sample)
        # Adaptive Proportion Test cutoff: binomial critical value for
        # p = 2^-H over `window` samples (normal approximation, +6 sigma margin).
        p = 2 ** -h_per_sample
        self.apt_window = window
        self.apt_cutoff = math.ceil(window * p + 6 * math.sqrt(window * p * (1 - p))) + 1
        self._last = None
        self._run = 0

    def check(self, samples: bytes) -> None:
        for s in samples:
            if s == self._last:
                self._run += 1
                if self._run >= self.rct_cutoff:
                    raise EntropyError(f"repetition count test failed ({self._run} repeats)")
            else:
                self._last, self._run = s, 1
        for i in range(0, len(samples) - self.apt_window + 1, self.apt_window):
            block = samples[i:i + self.apt_window]
            if block.count(block[0]) >= self.apt_cutoff:
                raise EntropyError("adaptive proportion test failed")


def mcv_min_entropy(samples: bytes) -> float:
    """Most Common Value estimator (SP 800-90B 6.3.1): min-entropy per sample,
    using the 99% upper confidence bound on the most common value's frequency."""
    n = len(samples)
    p_hat = max(collections.Counter(samples).values()) / n
    p_u = min(1.0, p_hat + 2.576 * math.sqrt(p_hat * (1 - p_hat) / (n - 1)))
    return -math.log2(p_u)


# --------------------------------------------------------------------------- #
# Entropy sources
# --------------------------------------------------------------------------- #

class EntropySource:
    name = "base"

    def available(self) -> bool:
        return True

    def read(self, nbytes: int) -> tuple[bytes, float]:
        """Return (data, credited entropy in bits)."""
        raise NotImplementedError


class OSSource(EntropySource):
    """Kernel CSPRNG. Already conditioned, so credited at full value."""
    name = "os"

    def read(self, nbytes):
        data = os.urandom(nbytes)
        return data, 8.0 * nbytes


class HWRNGSource(EntropySource):
    """Hardware RNG character device. Credited at half value as a hedge
    against a weak or untrusted device."""
    name = "hwrng"

    def __init__(self, path: str = "/dev/hwrng"):
        self.path = path

    def available(self):
        try:
            with open(self.path, "rb") as f:
                return len(f.read(1)) == 1
        except OSError:
            return False

    def read(self, nbytes):
        with open(self.path, "rb", buffering=0) as f:
            data = b""
            while len(data) < nbytes:
                chunk = f.read(nbytes - len(data))
                if not chunk:
                    raise EntropyError("hwrng returned no data")
                data += chunk
        if len(set(data)) == 1 and nbytes > 4:
            raise EntropyError("hwrng output is stuck")
        return data, 4.0 * nbytes


class JitterSource(EntropySource):
    """CPU execution-time jitter.

    Each sample times a small memory-touching workload with a nanosecond
    clock; the low byte of the delta between consecutive timings is the raw
    sample. Variation comes from caches, TLB, branch prediction, interrupts
    and frequency scaling. Entropy is estimated at start-up and credited
    conservatively (at most `max_credit` bits per sample)."""
    name = "jitter"

    def __init__(self, max_credit: float = 1.0, startup_samples: int = 4096):
        self._buf = bytearray(4096)
        self._clock = time.perf_counter_ns
        startup = self._raw(startup_samples)
        est = mcv_min_entropy(startup)
        if est < 0.1:
            raise EntropyError(f"jitter source too predictable (H={est:.3f})")
        self.h = min(est, max_credit)
        self.estimate = est
        self.health = HealthTests(self.h)
        self.health.check(startup)

    def _raw(self, n: int) -> bytes:
        buf, clock = self._buf, self._clock
        out = bytearray(n)
        prev = clock()
        idx = 0
        for i in range(n):
            for _ in range(32):              # variable-cost memory walk
                idx = (idx * 33 + 0x9E37 + buf[idx]) & 0xFFF
                buf[idx] = (buf[idx] + 1) & 0xFF
            now = clock()
            out[i] = (now - prev) & 0xFF
            prev = now
        return bytes(out)

    def read(self, nbytes):
        # Collect enough raw samples to credit nbytes*8 bits, then compress.
        n = math.ceil(nbytes * 8 / self.h)
        raw = self._raw(n)
        self.health.check(raw)
        return hashlib.shake_256(raw).digest(nbytes), min(8.0 * nbytes, n * self.h)


# --------------------------------------------------------------------------- #
# Entropy pool
# --------------------------------------------------------------------------- #

class EntropyPool:
    """Mixes all sources into a SHA-512 state and tracks credited entropy.

    Every source contributes on every gather, so the seed stays strong as long
    as *any one* source is good."""

    def __init__(self, sources: list[EntropySource]):
        self.sources = sources
        if not sources:
            raise EntropyError("no entropy sources available")
        self.failures: collections.Counter[str] = collections.Counter()

    def gather(self, bits: int = SEED_ENTROPY_BITS) -> bytes:
        """Mix every source into the pool. A source that raises EntropyError or
        OSError is skipped and counted in self.failures.

        Credits are not summed: the seed is accepted only if one source on its
        own credits `bits`. Half-credit sources (hwrng) add defence in depth but
        can never carry the seed, alone or together with others. A source cannot
        credit more than 8 bits per byte it returned."""
        h = hashlib.sha512(b"entropy-rng/pool/v1")
        best = 0.0
        per_source = math.ceil(bits / 8)
        for src in self.sources:
            try:
                data, ent = src.read(per_source)
            except (EntropyError, OSError):
                self.failures[src.name] += 1   # a failing source adds nothing
                continue
            h.update(src.name.encode() + len(data).to_bytes(4, "big") + data)
            best = max(best, min(ent, 8.0 * len(data)))
        h.update(time.time_ns().to_bytes(8, "big") + os.getpid().to_bytes(4, "big"))
        if best < bits:
            raise EntropyError(f"insufficient entropy: best single source {best:.0f}/{bits} bits")
        return h.digest()


# --------------------------------------------------------------------------- #
# HMAC-DRBG (NIST SP 800-90A Rev.1, section 10.1.2) with SHA-256
# --------------------------------------------------------------------------- #

class HMACDRBG:
    # K and V are bytearrays updated in place, so wipe() can overwrite them.
    # Intermediate bytes objects inside hmac/hashlib are beyond our reach.
    def __init__(self, entropy: bytes, nonce: bytes = b"", personalization: bytes = b""):
        self.K = bytearray(32)
        self.V = bytearray(b"\x01" * 32)
        self._update(entropy + nonce + personalization)
        self.reseed_counter = 1

    def _hmac(self, key, data):
        return hmac.new(key, data, hashlib.sha256).digest()

    def _update(self, provided: bytes = b"") -> None:
        self.K[:] = self._hmac(self.K, self.V + b"\x00" + provided)
        self.V[:] = self._hmac(self.K, self.V)
        if provided:
            self.K[:] = self._hmac(self.K, self.V + b"\x01" + provided)
            self.V[:] = self._hmac(self.K, self.V)

    def wipe(self) -> None:
        self.K[:] = bytes(32)
        self.V[:] = bytes(32)
        self.reseed_counter = 0

    def reseed(self, entropy: bytes, additional: bytes = b"") -> None:
        self._update(entropy + additional)
        self.reseed_counter = 1

    def generate(self, nbytes: int, additional: bytes = b"") -> bytes:
        if nbytes > MAX_REQUEST_BYTES:
            raise ValueError("request too large")
        if additional:
            self._update(additional)
        out = bytearray()
        while len(out) < nbytes:
            self.V[:] = self._hmac(self.K, self.V)
            out += self.V
        self._update(additional)
        self.reseed_counter += 1
        return bytes(out[:nbytes])


# --------------------------------------------------------------------------- #
# Public generator
# --------------------------------------------------------------------------- #

def default_sources() -> list[EntropySource]:
    sources: list[EntropySource] = [OSSource()]
    hw = HWRNGSource()
    if hw.available():
        sources.append(hw)
    try:
        sources.append(JitterSource())
    except EntropyError:
        pass
    return sources


# One at-fork hook for all generators. A per-instance hook would keep every
# instance (and its DRBG state) alive for the life of the process.
_instances: weakref.WeakSet[EntropyRNG] = weakref.WeakSet()


def _after_fork_in_child() -> None:
    # Only replace the locks: another thread may have held one during fork().
    # The reseed itself happens lazily on the next request (pid check).
    for rng in list(_instances):
        rng._lock = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)

# Suspend/resume (and VM restores the guest kernel accounts as suspended time)
# moves CLOCK_BOOTTIME away from CLOCK_MONOTONIC.
CLOCK_SKEW_RESEED_NS = 1_000_000_000


def _clock_skew() -> int:
    if not hasattr(time, "CLOCK_BOOTTIME"):
        return 0
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME) - time.clock_gettime_ns(time.CLOCK_MONOTONIC)


class EntropyRNG:
    """Thread- and fork-safe CSPRNG seeded from multiple entropy sources.

    prediction_resistance=True reseeds from the pool before every request
    (slower, but compromise of the internal state does not reveal future output,
    and a cloned VM or restored snapshot does not repeat output). Use it for keys.

    Call close() (or use `with EntropyRNG() as rng:`) to overwrite the DRBG state.
    """

    def __init__(self, sources: list[EntropySource] | None = None,
                 personalization: bytes = b"", prediction_resistance: bool = False):
        self.pool = EntropyPool(sources if sources is not None else default_sources())
        self.prediction_resistance = prediction_resistance
        self._lock = threading.Lock()
        seed = self.pool.gather(SEED_ENTROPY_BITS + SEED_ENTROPY_BITS // 2)  # entropy + nonce
        self._drbg: HMACDRBG | None = HMACDRBG(seed, personalization=personalization)
        self._pid = os.getpid()
        self._skew = _clock_skew()
        _instances.add(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        """Overwrite K and V (best effort) and stop using this generator."""
        with self._lock:
            if self._drbg is not None:
                self._drbg.wipe()
                self._drbg = None
        _instances.discard(self)

    def _reseed(self, additional: bytes = b"") -> None:
        self._drbg.reseed(self.pool.gather(), additional)
        self._pid = os.getpid()
        self._skew = _clock_skew()

    def random_bytes(self, n: int) -> bytes:
        with self._lock:
            if self._drbg is None:
                raise ValueError("generator is closed")
            if os.getpid() != self._pid:
                self._reseed(b"fork")
            if abs(_clock_skew() - self._skew) > CLOCK_SKEW_RESEED_NS:
                self._reseed(b"resume")    # the state may now exist twice
            out = bytearray()
            while len(out) < n:
                if self.prediction_resistance or self._drbg.reseed_counter > RESEED_INTERVAL:
                    self._reseed()
                out += self._drbg.generate(min(n - len(out), MAX_REQUEST_BYTES))
            result = bytes(out)
            out[:] = bytes(len(out))
            return result

    def randbits(self, k: int) -> int:
        if k <= 0:
            return 0
        v = int.from_bytes(self.random_bytes((k + 7) // 8), "big")
        return v >> (-k % 8)

    def randbelow(self, n: int) -> int:
        """Uniform integer in [0, n) by rejection sampling (no modulo bias)."""
        if n <= 0:
            raise ValueError("n must be positive")
        k = n.bit_length()
        while True:
            r = self.randbits(k)
            if r < n:
                return r

    def randint(self, a: int, b: int) -> int:
        return a + self.randbelow(b - a + 1)

    def random(self) -> float:
        """Uniform float in [0.0, 1.0) with 53 random bits."""
        return self.randbits(53) / (1 << 53)

    def describe(self) -> str:
        parts = []
        for s in self.pool.sources:
            if isinstance(s, JitterSource):
                parts.append(f"jitter (measured H={s.estimate:.2f} bits/sample, credited {s.h:.2f})")
            else:
                parts.append(s.name)
        text = "sources: " + ", ".join(parts)
        if self.pool.failures:
            text += " [failures: " + ", ".join(f"{k}={v}" for k, v in sorted(self.pool.failures.items())) + "]"
        return text


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Entropy-based CSPRNG")
    ap.add_argument("-n", type=int, default=32, help="bytes to output")
    ap.add_argument("--raw", action="store_true", help="write raw bytes to stdout")
    ap.add_argument("--stream", action="store_true", help="write raw bytes forever (for dieharder/ent)")
    ap.add_argument("--pr", action="store_true", help="prediction resistance")
    args = ap.parse_args()

    rng = EntropyRNG(prediction_resistance=args.pr)
    if args.stream:
        try:
            while True:
                sys.stdout.buffer.write(rng.random_bytes(65536))
        except BrokenPipeError:
            pass
    elif args.raw:
        sys.stdout.buffer.write(rng.random_bytes(args.n))
    else:
        print(rng.describe(), file=sys.stderr)
        print(rng.random_bytes(args.n).hex())

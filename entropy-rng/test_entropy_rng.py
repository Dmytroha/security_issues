import collections, math, os, unittest
from entropy_rng import (HMACDRBG, EntropyRNG, EntropyError, HealthTests,
                         JitterSource, OSSource, EntropySource, mcv_min_entropy)


class TestHMACDRBG(unittest.TestCase):
    def test_nist_cavp_vector(self):
        # NIST CAVP HMAC_DRBG.rsp, [SHA-256] PredictionResistance=False,
        # no reseed, no personalization/additional input, COUNT = 0.
        e = bytes.fromhex("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488")
        n = bytes.fromhex("659ba96c601dc69fc902940805ec0ca8")
        expected = bytes.fromhex(
            "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89"
            "d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1"
            "07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668"
            "961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8")
        d = HMACDRBG(e, n)
        d.generate(128)
        self.assertEqual(d.generate(128), expected)


class TestHealth(unittest.TestCase):
    def test_stuck_source_rejected(self):
        with self.assertRaises(EntropyError):
            HealthTests(1.0).check(b"\x07" * 100)

    def test_apt(self):
        ht = HealthTests(2.0)          # claims p_max = 1/4
        with self.assertRaises(EntropyError):
            ht.check(bytes([5, 6] * 256))   # value 5 is 50% of window

    def test_random_passes(self):
        HealthTests(1.0).check(os.urandom(4096))
        self.assertGreater(mcv_min_entropy(os.urandom(1 << 16)), 7.3)


class TestRNG(unittest.TestCase):
    def setUp(self):
        self.rng = EntropyRNG()

    def test_jitter_source_works(self):
        j = JitterSource()
        data, ent = j.read(32)
        self.assertEqual(len(data), 32)
        self.assertGreaterEqual(ent, 255)

    def test_distinct_instances(self):
        self.assertNotEqual(EntropyRNG().random_bytes(32), EntropyRNG().random_bytes(32))

    def test_jitter_only_seeding(self):
        rng = EntropyRNG(sources=[JitterSource()])
        self.assertEqual(len(rng.random_bytes(64)), 64)

    def test_insufficient_entropy(self):
        class Weak(EntropySource):
            name = "weak"
            def read(self, n): return b"\x00" * n, 1.0
        with self.assertRaises(EntropyError):
            EntropyRNG(sources=[Weak()])

    def test_byte_distribution(self):
        data = self.rng.random_bytes(1 << 20)
        c = collections.Counter(data)
        exp = len(data) / 256
        chi2 = sum((c[i] - exp) ** 2 / exp for i in range(256))
        self.assertLess(chi2, 340)    # df=255, p≈0.0003
        ones = sum(bin(b).count("1") for b in data)
        z = (ones - 4 * len(data)) / math.sqrt(2 * len(data))
        self.assertLess(abs(z), 4.5)

    def test_randbelow_uniform(self):
        c = collections.Counter(self.rng.randbelow(6) for _ in range(60000))
        self.assertEqual(set(c), set(range(6)))
        for v in c.values():
            self.assertLess(abs(v - 10000), 500)

    def test_fork_reseeds(self):
        self.rng.random_bytes(16)
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.write(w, self.rng.random_bytes(32)); os._exit(0)
        os.waitpid(pid, 0)
        child = os.read(r, 32)
        self.assertNotEqual(child, self.rng.random_bytes(32))

    def test_prediction_resistance(self):
        rng = EntropyRNG(prediction_resistance=True)
        self.assertEqual(len(rng.random_bytes(100)), 100)


if __name__ == "__main__":
    unittest.main()

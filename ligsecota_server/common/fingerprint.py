"""
Simulated bit-time fingerprinting (Handbook Chapters 3 and 10).

No real CAN-FD hardware is available in this environment, so oscillator
behaviour is modelled rather than measured: each simulated ECU has a fixed
per-device timing offset ("ppm-like" drift) plus per-measurement jitter.
This is enough to demonstrate:

  * enrolment producing a stable per-device fingerprint (Ch. 3.4-3.5)
  * F1 / F7: a classifier (or, as here, a simple similarity check) that
    is asked "is this the enrolled device?" rather than "which of N
    classes is this?" -- the open-set framing from Handbook 10.3
  * the central finding (F1, Handbook 18.1): v1 never re-checks the
    fingerprint at runtime, so a cloned key on different "silicon"
    (a different simulated oscillator) authenticates successfully. v2's
    live check catches it.

Label every result from this module as SIMULATED in any writeup --
see Handbook 10.5.
"""
import random

import numpy as np
from scipy import stats


class SimulatedOscillator:
    """One physical device. `offset_ns` stands in for crystal ppm error;
    `jitter_ns` is per-bit measurement noise."""

    def __init__(self, device_id, offset_ns, jitter_ns=2.0, seed=None):
        self.device_id = device_id
        self.offset_ns = offset_ns
        self.jitter_ns = jitter_ns
        self.rng = random.Random(seed if seed is not None else hash(device_id))

    def sample_bit_times(self, n=500, nominal_ns=1000.0):
        return np.array([
            nominal_ns + self.offset_ns + self.rng.gauss(0, self.jitter_ns)
            for _ in range(n)
        ])


def features(bit_times: np.ndarray) -> np.ndarray:
    """The paper's seven time-domain statistics (Handbook 3.4 / 10.1)."""
    x = np.asarray(bit_times, dtype=np.float64)
    return np.array([
        x.mean(), x.std(ddof=1), x.var(ddof=1),
        stats.skew(x), stats.kurtosis(x),
        np.sqrt((x ** 2).mean()), (x ** 2).sum(),
    ])


def enroll(oscillator: SimulatedOscillator, n=500) -> np.ndarray:
    """Factory-time fingerprint: Chapter 3.5, stage 1-2."""
    return features(oscillator.sample_bit_times(n=n))


def similarity(observed: np.ndarray, enrolled: np.ndarray) -> float:
    """Normalised distance on the two features that actually carry
    independent signal (mean offset, jitter) -- see Handbook 3.4's note
    on redundancy among the seven features. Returns a score in [0, 1],
    1.0 = identical."""
    d_mean = abs(observed[0] - enrolled[0])
    d_std = abs(observed[1] - enrolled[1])
    score = 1.0 / (1.0 + d_mean + d_std)
    return score


def live_check(oscillator: SimulatedOscillator, enrolled: np.ndarray,
                threshold: float, n=200) -> bool:
    """What v2's gateway does during the handshake that v1 never does at
    all (Handbook 8.4 / 17.4, Finding F1): re-measure and compare against
    the certificate's enrolled fingerprint."""
    observed = features(oscillator.sample_bit_times(n=n))
    return similarity(observed, enrolled) >= threshold

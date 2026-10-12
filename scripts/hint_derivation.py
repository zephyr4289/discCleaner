#!/usr/bin/env python3
"""Derive the correct ML-DSA hint (predicate, correction) pair by brute force.

Simulates honest signing tuples (x = w, delta = c*t0 - c*s2) under the
ML-DSA-44 parameters and the r0-rejection constraint, then tests candidate
1-bit hint mechanisms. If none works, proves it and reports.
"""
import random

Q = 8380417
GAMMA2 = 95232
BETA = 78
TAU = 39
T0MAX = 4095          # |t0 coeff| <= 2^12 - 1... use 2^(d-1) bound
CT0MAX = TAU * T0MAX  # 159,705

def decompose(rp):
    r1 = (rp + GAMMA2 - 1) // (2 * GAMMA2)
    if r1 == 44:
        return (0, rp - (Q - 1))
    return (r1, rp - r1 * 2 * GAMMA2)

def bucket(rp):
    return decompose(rp)[0]

def lowbits(rp):
    return decompose(rp)[1]

random.seed(0xC0FFEE)
N_TRIALS = 200000
samples = []
while len(samples) < N_TRIALS:
    x = random.randrange(Q)
    # c*t0 coefficient: sum of 39 terms (+-1)*(t0 coeff in [-4096,4095])
    # simulate realistic magnitudes: normal-ish sum
    ct0 = sum(random.choice([-1, 1]) * random.randint(-4096, 4095) for _ in range(TAU))
    ct0 = max(-CT0MAX, min(CT0MAX, ct0))
    cs2 = sum(random.choice([-1, 1]) * random.randint(-2, 2) for _ in range(TAU))
    # r0-rejection honesty constraint on LowBits(w - c*s2)
    v = (x - cs2) % Q
    if abs(lowbits(v)) >= GAMMA2 - BETA:
        continue
    y = (x + ct0 - cs2) % Q
    samples.append((x, y, ct0, cs2))

print(f"built {len(samples)} honest tuples")

# What corrections are needed?
from collections import Counter
dirs = Counter()
for (x, y, ct0, cs2) in samples:
    d = (bucket(x) - bucket(y)) % 44
    if d == 43: d = -1
    dirs[d] += 1
print("needed correction distribution (b_x - b_y):", dict(dirs))

# Candidate predicates (signer side, knows x and y) and corrections
# (verifier side, knows y, h). A mechanism works iff for all tuples:
#   C(P(x,y), y) == bucket(x)
def c_plus1(h, y):
    b, m = decompose(y)
    return (b + 1) % 44 if h else b

def c_minus1(h, y):
    b, m = decompose(y)
    return (b - 1) % 44 if h else b

def c_msign_pos(h, y):   # h=1: +1 if m<=0 else -1
    b, m = decompose(y)
    if not h: return b
    return (b + 1) % 44 if m <= 0 else (b - 1) % 44

def c_msign_neg(h, y):   # h=1: +1 if m>0 else -1
    b, m = decompose(y)
    if not h: return b
    return (b + 1) % 44 if m > 0 else (b - 1) % 44

def p_crossing(x, y):
    return bucket(x) != bucket(y)

def p_dir_plus(x, y):
    return (bucket(x) - bucket(y)) % 44 == 1

def p_dir_minus(x, y):
    return (bucket(x) - bucket(y)) % 44 == 43

def p_m_low(x, y):  # h = 1 iff the signer's low part <= verifier's low part
    return lowbits(x) <= lowbits(y)

mechanisms = [
    ("h=crossing, C=+1",        p_crossing, c_plus1),
    ("h=crossing, C=-1",        p_crossing, c_minus1),
    ("h=crossing, C=msign_pos", p_crossing, c_msign_pos),
    ("h=crossing, C=msign_neg", p_crossing, c_msign_neg),
    ("h=dir+1, C=+1",           p_dir_plus, c_plus1),
    ("h=dir-1, C=-1",           p_dir_minus, c_minus1),
    ("h=dir+1, C=msign_pos",    p_dir_plus, c_msign_pos),
    ("h=m_low, C=+1",           p_m_low, c_plus1),
]

for name, P, C in mechanisms:
    bad = 0
    for (x, y, ct0, cs2) in samples:
        h = 1 if P(x, y) else 0
        if C(h, y) != bucket(x):
            bad += 1
            if bad <= 3:
                print(f"  [{name}] FAIL: x={x} y={y} b_x={bucket(x)} b_y={decompose(y)[0]} m_y={decompose(y)[1]} h={h} got={C(h,y)}")
    status = "WORKS FOR ALL TUPLES" if bad == 0 else f"fails {bad}/{len(samples)}"
    print(f"{name}: {status}")

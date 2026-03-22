"""
Reference implementation of anamorphic El-Gamal encrpytion from appendix C from the paper.

We gotta redo this in rust and add stuff ig.
"""

import random
from Crypto.Cipher import AES


class PublicParams:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g


class AnamParams:
    def __init__(self, l, s, t):
        self.F = lambda pp, K, x, y: (
            int.from_bytes(
                AES.new(K, AES.MODE_ECB).encrypt(
                    x.to_bytes(8, "little") + y.to_bytes(8, "little")
                ),
                "little",
            )
            % pp.p
        )
        self.d = lambda ap, x: x % ap.t
        self.l = l
        self.s = s
        self.t = t


class KeyPair:
    def __init__(self, sk, pk):
        self.sk = sk
        self.pk = pk


class DoubleKey:
    def __init__(self, K, T, pk):
        self.K = K
        self.T = T
        self.pk = pk


def Gen(pp):
    sk = random.randint(0, pp.q - 1)
    pk = pow(pp.g, sk, pp.p)
    return KeyPair(sk, pk)


def Enc(pp, pk, msg):
    r = random.randint(0, pp.q - 1)
    c0 = (msg * pow(pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    return c0, c1


def Dec(pp, sk, c):
    return (c[0] * pow(c[1], -sk, pp.p)) % pp.p


def aGen(pp, ap, pk):
    K = random.randbytes(16)
    T = dict()
    for i in range(ap.l):
        T[pow(pp.g, i, pp.p)] = i

    return DoubleKey(K, T, pk)


def aEncCtr(pp, ap, dk, msg, cm, ctr):
    found = False
    for x in range(ctr[0], ap.s):
        for y in range(ctr[1], ap.t):
            t = ap.F(pp, dk.K, x, y)
            r = (cm + t) % pp.q

            if ap.d(ap, pow(pp.g, r, pp.p)) == y:
                found = True
                break

        if found:
            break

    ctr[1] = 0
    ctr[0] = (x + (1 if y == ap.t - 1 else 0)) % ap.s
    ctr[1] = (y + 1) % ap.t
    c0 = (msg * pow(dk.pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    ctx = (c0, c1)
    return ctx, ctr


def aEnc(pp, ap, dk, msg, cm):
    while True:
        x = random.randint(0, ap.s - 1)
        y = random.randint(0, ap.t - 1)
        t = ap.F(pp, dk.K, x, y)
        r = (cm + t) % pp.q
        if ap.d(ap, pow(pp.g, r, pp.p)) == y:
            break

    c0 = (msg * pow(dk.pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    ctx = (c0, c1)
    return ctx


def aDec(pp, ap, dk, ctx):
    y = ap.d(ap, ctx[1])
    for x in range(ap.s):
        t = ap.F(pp, dk.K, x, y)
        s = (ctx[1] * pow(pp.g, -t, pp.p)) % pp.p
        if s in dk.T:
            return dk.T[s]

    return -1


# Settings
runs = 50

# Public Parameters (safe prime, pow(g, (p - 1) // 2, p) != 1)
# p, g = int("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
# 29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
# EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
# E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
# EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\
# FFFFFFFFFFFFFFFF", 0), 5 # Oakley group (RFC 2409)
p, g = 1000000007, 5
q = p - 1
pp = PublicParams(p, q, g)
print("p =", pp.p)
print("q =", pp.q)
print("g =", pp.g)

# Anamorphic Parameters
l = 100
s = 100
t = 100
ap = AnamParams(l, s, t)
print("l =", ap.l)
print("s =", ap.t)
print("t =", ap.s)

# Keys Generation
kp = Gen(pp)
dk = aGen(pp, ap, kp.pk)
print("(sk, pk) = (%d, %d)" % (kp.sk, kp.pk))
print("K =", dk.K)
print(
    "T = [",
    ", ".join(
        str(a) + "->" + str(b)
        for (a, b) in sorted([((pp.g**i) % pp.p, i) for i in range(l)])
    ),
    "]",
)

# Testing aEnc -> Dec and aEnc -> aDec
msg = random.randint(1, pp.p - 1)
cm = random.randint(0, l - 1)
# ctr = [0, 0]
for i in range(runs):
    # c, ctr = aEncCtr(pp, dk, msg, cm, ctr)
    ctx = aEnc(pp, ap, dk, msg, cm)
    msg_ = Dec(pp, kp.sk, ctx)
    cm_ = aDec(pp, ap, dk, ctx)
    print("(%d, %d) -> aEnc -> (%d, %d) -> Dec -> %d" % (msg, cm, ctx[0], ctx[1], msg_))
    print("(%d, %d) -> aEnc -> (%d, %d) -> aDec -> %d" % (msg, cm, ctx[0], ctx[1], cm_))

# Testing Enc -> Dec and Enc -> aDec
for i in range(runs):
    m = random.randint(1, pp.p - 1)
    ctx = Enc(pp, kp.pk, m)
    msg_ = Dec(pp, kp.sk, ctx)
    cm_ = aDec(pp, ap, dk, ctx)
    print("%d -> Enc -> (%d, %d) -> Dec -> %d" % (m, ctx[0], ctx[1], msg_))
    print(
        "%d -> Enc -> (%d, %d) -> aDec -> %d" % (m, ctx[0], ctx[1], cm_),
        "(!)" if cm_ != -1 else "",
    )

import secrets

# Parameters for the Weierstrass form of Curve25519
p = 2 ** 255 - 19
# Coefficients a and b of the curve
a = 19298681539552699237261830834781317975544997444273427339909597334573241639236
b = 55751746669818908907645289078257140818241103727901012315294400837956729358436
# Coordinates of the generator
Gx = 19298681539552699237261830834781317975544997444273427339909597334652188435546
Gy = 14781619447589544791020593568409986887264606134616475288964881837755586237401
n = 2 ** 252 + 27742317777372353535851937790883648493


# Test if a point is in the curve by checking if y^2 = x^3 + ax + b over Fp.
def is_on_curve(P):
    """ Check if a point P is on the curve """
    if P is None:
        return True
    x, y = P
    return (y * y) % p == (x * x * x + a * x + b) % p


# Add points in the curve
def point_addition(P, Q):
    assert is_on_curve(P), "Point P is not on the curve"
    assert is_on_curve(Q), "Point Q is not on the curve"
    """ Add two distinct points P and Q in affine coordinates """
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and y1 != y2:
        return None  # Point at infinity

    if x1 == x2 and y1 == y2:
        return point_doubling(P)

    # --------- add your code here --------
    lamb = ((y2 - y1) / (x2 - x1)) % p
    x3 = ((lamb ** 2) - x1 - x2) % p
    y3 = (lamb * (x1 - x3) - y1) % p
    # ----- end add your code here --------
    return (x3, y3)


def point_doubling(P):
    assert is_on_curve(P), "Point P is not on the curve"
    """ Double a point P in affine coordinates """
    if P is None:
        return None
    x1, y1 = P

    # --------- add your code here --------
    lamb = (((3 * (x1 ** 2) ) + a) / (2 * y1)) % p
    x3 = ((lamb ** 2) - 2*x1) % p
    y3 = (lamb * (x1 - x3) - y1) % p
    # ----- end add your code here --------
    return (x3, y3)


def scalar_mult(k, P):
    """ Compute k * P using double-and-add """
    assert is_on_curve(P), "Point P is not on the curve"
    R = None  # Point at infinity
    top_bit = 1 << (k.bit_length() - 1)

    while top_bit:
        R = point_doubling(R)
        if k & top_bit:
            R = point_addition(R, P)
        top_bit >>= 1
    return R


def montgomery_ladder(k, P):
    """ Compute k * P using the Montgomery ladder """
    assert is_on_curve(P), "Point P is not on the curve"
    R0, R1 = None, P
    return R0


# Example usage: compute k * G
P = (Gx, Gy)
assert is_on_curve(P), "Generator point is not on the curve"

sk_alice = secrets.randbelow(n)
sk_bob = secrets.randbelow(n)

PK_alice = scalar_mult(sk_alice, P)
PK_bob = scalar_mult(sk_bob, P)

K1 = scalar_mult(sk_alice, PK_bob)
K2 = scalar_mult(sk_bob, PK_alice)

assert (K1 == K2), "Diffie-Hellman does not compute the same shared secret"
print("If everything is correct, the points below must be equal: ")
print(K1)
print(K2)

assert (scalar_mult(sk_alice, PK_bob) == montgomery_ladder(sk_alice, PK_bob)), "Montgomery ladder is wrong"
assert (scalar_mult(sk_bob, PK_alice) == montgomery_ladder(sk_bob, PK_alice)), "Montgomery ladder is wrong"
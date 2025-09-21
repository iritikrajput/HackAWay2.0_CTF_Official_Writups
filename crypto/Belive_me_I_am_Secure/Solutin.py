'''After Carefully analyzing the json file it come to knowledge that The public key uses a very small private exponent d. 
That makes the key vulnerable to Wiener’s attack (small-d attack). Using continued-fraction convergents of e/N we recover
 d without factoring N directly. With d we decrypt c to get the flag.
'''
# wiener_solve.py
from math import isqrt

N = 104573064464321935519910414868044616405386213002087014488733157109599228878120159209570195885316437885630775458740821071976396412564458514345706738058155474637570138551939698150382213288431808899144048647233832551057760550078729269489931656130308267678296454303387464188560010271865334913377763138234239233571
e = 5649217095673259637398231249239129698359548511994925097711736208417745660062191625827284840490942006092107200308553052681918673650510398694170297054377134651978053376643587960043519436823541928643437235742378670428043502332382258628104079292812407156978089512214555739453438370773930876303415041465796588989
c = 79851606723352104032416421688830014739986513790517448961127562082725981582211092008740747284718187254218427600475791917669814460178631998376958916906098709348452537728832655695778491550203560491914547202979790867193797696497151856443265967406785258493145238189843010398329395538915869679215074797519051504077

def continued_fraction(a, b):
    cf = []
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a - q * b
    return cf

def convergents_from_cf(cf):
    convs = []
    for i in range(len(cf)):
        num, den = 1, 0
        for q in reversed(cf[:i+1]):
            num, den = q * num + den, num
        convs.append((num, den))
    return convs

def is_perfect_square(n):
    if n < 0:
        return False
    r = isqrt(n)
    return r*r == n

def wiener_attack(e, N):
    cf = continued_fraction(e, N)
    convs = convergents_from_cf(cf)
    for k, d in convs:
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = N - phi + 1
        discr = s*s - 4*N
        if discr < 0:
            continue
        if not is_perfect_square(discr):
            continue
        t = isqrt(discr)
        p = (s + t) // 2
        q = (s - t) // 2
        if p * q == N:
            return int(d), int(p), int(q)
    return None, None, None

d, p, q = wiener_attack(e, N)
if d is None:
    print("Wiener's attack failed: no small d found.")
else:
    print("Found d:", d)
    m = pow(c, d, N)
    length = (m.bit_length() + 7) // 8
    plaintext = m.to_bytes(length, 'big') if m != 0 else b""
    try:
        print("Plaintext:", plaintext.decode('utf-8'))
    except:
        print("Plaintext (hex):", plaintext.hex())

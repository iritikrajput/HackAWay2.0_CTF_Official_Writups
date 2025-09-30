#!/usr/bin/env python3
import re

C1_HEX = "4b986c6738727c77716946082c312732015e5f7514"
C2_HEX = "051a1d3915572a1c60745d04082a6c26044a12050a"

c1 = bytes.fromhex(C1_HEX)
c2 = bytes.fromhex(C2_HEX)
L = min(len(c1), len(c2))

# 1) compute X = C1 ^ C2
x = bytes((a ^ b) for a, b in zip(c1, c2))
print("C1 ^ C2 =", x.hex())

# 2) crib-drag with "CCUJ"
crib = b"CCUJ"
print("\nTrying crib:", crib.decode())

def is_printable(bts):
    return all(32 <= b < 127 for b in bts)

candidates = []
for pos in range(L - len(crib) + 1):
    derived = bytes(x[pos + i] ^ crib[i] for i in range(len(crib)))
    if is_printable(derived):
        candidates.append((pos, derived))

print("Printable candidates (pos, derived-bytes from the other plaintext):")
for pos, d in candidates:
    print(" pos", pos, "->", d)

# We'll pick the most plausible candidate (organizer-known: crib aligns such that we reveal readable text).
# In this challenge the solver would inspect candidates and pick the alignment that yields English-like text.
# For automation, try each viable candidate and see which yields a full flag-like structure after key extension.

def decrypt_with_key_bytes(ct, key_bytes):
    out = []
    for i, b in enumerate(ct):
        k = key_bytes[i]
        if k is None:
            out.append(ord('?'))
        else:
            out.append(b ^ k)
    return bytes(out)

# Try each candidate alignment to derive partial key and heuristically extend
for pos, derived in candidates:
    # derive key bytes for the crib placement (key[pos + j] = c1[pos + j] ^ crib[j])
    key = [None] * L
    for j in range(len(crib)):
        key[pos + j] = c1[pos + j] ^ crib[j]

    p1_partial = decrypt_with_key_bytes(c1, key)
    p2_partial = decrypt_with_key_bytes(c2, key)
    print("\n--- trying pos", pos, "---")
    print("Partial P1:", p1_partial)
    print("Partial P2:", p2_partial)

    # Heuristic extension: fill other key bytes if both resulting plaintext bytes are printable
    changed = True
    while changed:
        changed = False
        for i in range(L):
            if key[i] is None:
                # try candidate plaintext byte for p1 within printable range
                for cand in range(32, 127):
                    k_cand = c1[i] ^ cand
                    p2b = c2[i] ^ k_cand
                    if 32 <= p2b < 127:
                        key[i] = k_cand
                        changed = True
                        break

    p1_full = decrypt_with_key_bytes(c1, key)
    # check for flag pattern like CCUJ{...}
    m = re.search(rb"CCUJ\{[A-Za-z0-9_]+\}", p1_full)
    print("Heuristically decrypted P1:", p1_full)
    if m:
        print("Flag candidate found:", m.group(0).decode())
        break
else:
    print("\nNo full flag recovered automatically from candidates. Inspect partial outputs above and continue manually.")

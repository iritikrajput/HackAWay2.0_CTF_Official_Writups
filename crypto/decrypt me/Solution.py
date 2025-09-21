# verify_flag.py
from binascii import unhexlify

c1 = unhexlify("4b986c6738727c77716946082c312732015e5f7514")
c2 = unhexlify("051a1d3915572a1c60745d04082a6c26044a12050a")
flag = b"CCUJ{X0R_reus3_is_b4d}"

def try_flag_in(ct, other_ct, flag):
    # try placing flag at every possible offset in ct
    for pos in range(len(ct) - len(flag) + 1):
        # derive keystream for the flag region
        keystream = bytearray(len(ct))
        for i in range(len(flag)):
            keystream[pos + i] = ct[pos + i] ^ flag[i]
        # fill remaining keystream bytes using other_ct -> require printable plaintexts (optional)
        for i in range(len(ct)):
            if keystream[i] == 0:
                # infer candidate from assuming printable plaintexts (32..126)
                # pick one printable value if possible
                found=False
                for k in range(256):
                    p1 = ct[i] ^ k
                    p2 = other_ct[i] ^ k
                    if 32 <= p1 <= 126 and 32 <= p2 <= 126:
                        keystream[i] = k
                        found=True
                        break
                if not found:
                    keystream[i] = 0  # leave as 0 (can't infer)
        # decrypt both
        p1 = bytes(ct[i] ^ keystream[i] for i in range(len(ct)))
        p2 = bytes(other_ct[i] ^ keystream[i] for i in range(len(ct)))
        if flag in p1 or flag in p2:
            print("Flag found at pos", pos, "in ct:", p1, p2)
            return True
    return False

print("flag in c1?", try_flag_in(c1, c2, flag))
print("flag in c2?", try_flag_in(c2, c1, flag))

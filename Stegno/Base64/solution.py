# This challenge all about read the Blog That we provide figureout the property that helps to hide the data and decode it.
# If you are not able to understand the blog so just feed it to AI it will help you to understand the blog and also make a pyhton script to decode the data for you.
# Save this as decode_stego_b64.py and run with Python 3

import base64

tokens = """U0==
Tz==
Uk==
Uj==
WV==
IF==
VE==
SK==
RX==
Ur==
RU==
IC==
ST==
U0==
IF==
Tj==
T0==
IF==
Rj==
TG==
QT==
R0==
IF==
VP==
T0==
II==
Qj==
RU==
IF==
Rm==
Tz==
VT==
Tl==
RP==
IE==
SH==
RT==
Ug==
RT==
Lg==
IE==
UE==
TF==
Rf==
QV==
Uw==
RV==
IC==
RD==
Tw==
IF==
Tg==
Tz==
VD==
IF==
Qy==
T1==
Tk==
VD==
SR==
Tk==
VV==
RV==
ID==
TH==
T9==
Tw==
Sw==
SQ==
Tg==
Ry4=""".splitlines()

b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
alpha_map = {c:i for i,c in enumerate(b64_alphabet)}

decoded_chars = []
stego_bits = []

for t in tokens:
    t = t.strip()
    if not t:
        continue
    # Normal decode
    try:
        dec = base64.b64decode(t)
        decoded_chars.append(dec.decode('latin1'))
    except Exception as e:
        decoded_chars.append(f"[decode error: {e}]")
    
    pad_len = t.count('=')
    core = t.rstrip('=')
    vals = [alpha_map.get(ch, None) for ch in core]
    if any(v is None for v in vals):
        continue
    
    if pad_len == 2:
        # 1 input byte -> 4 unused bits in second char
        c2 = vals[1] if len(vals) > 1 else 0
        unused4 = c2 & 0b1111
        stego_bits.append(format(unused4, '04b'))
    elif pad_len == 1:
        # 2 input bytes -> 2 unused bits in third char
        c3 = vals[2] if len(vals) > 2 else 0
        unused2 = c3 & 0b11
        stego_bits.append(format(unused2, '02b'))
    else:
        pass

normal_message = ''.join(decoded_chars)
print("Decoded message (normal Base64 decode):\n")
print(normal_message)
print("\n---\n")

bitstream = ''.join(stego_bits)
print(f"Collected stego bit groups (count={len(stego_bits)}):")
print(','.join(stego_bits))
print("\nCombined bitstream length:", len(bitstream))

bytes_list = []
for i in range(0, len(bitstream) - 7, 8):
    byte = bitstream[i:i+8]
    bytes_list.append(int(byte, 2))

if bytes_list:
    hidden = bytes(bytearray(bytes_list)).decode('latin1', errors='replace')
    print("\nHidden message extracted from unused bits (by grouping into 8-bit bytes):")
    print(hidden)
else:
    print("\nNo full bytes could be formed from the collected stego bits.")

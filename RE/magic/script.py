# Decoding the secret and flag by XORing with 0x13
enc_secret = "`fcva`vpavg"
enc_flag = 'PPFYhK#ALD"$[LA L"@LU#]n'
key = 0x13

dec_secret = ''.join(chr(ord(c) ^ key) for c in enc_secret)
dec_flag = ''.join(chr(ord(c) ^ key) for c in enc_flag)

print("Decoded secret (magic word):", dec_secret)
print("Decoded flag:", dec_flag)

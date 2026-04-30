"""
SNOW-SCA CTF — challenge generator
Encrypts a flag using SNOW-V and writes:
  - ciphertext (hex)
  - IV (hex)
  - challenge.txt  (what you hand to contestants)

SNOW-V reference: Ekdahl et al. 2019
https://tosc.iacr.org/index.php/ToSC/article/view/8356
"""

import os
import struct

# ---------------------------------------------------------------------------
# GF(2^16) helpers  (primitive polynomial x^16 + x^12 + x^10 + x^2 + 1)
# ---------------------------------------------------------------------------

ALPHA       = 0x990F   # mul_x constant for LFSR-A
ALPHA_INV   = 0xCC87   # mul_x_inv constant for LFSR-A
BETA        = 0xC963   # mul_x constant for LFSR-B
BETA_INV    = 0xE4B1   # mul_x_inv constant for LFSR-B

def mul_x(v: int, c: int) -> int:
    """Multiply v by x in GF(2^16); if MSB set, XOR with c."""
    if v & 0x8000:
        return ((v << 1) & 0xFFFF) ^ c
    return (v << 1) & 0xFFFF

def mul_x_inv(v: int, d: int) -> int:
    """Multiply v by x^-1 in GF(2^16); if LSB set, XOR with d after shift."""
    if v & 0x0001:
        return (v >> 1) ^ d
    return v >> 1

# ---------------------------------------------------------------------------
# AES-128 round (single round, key = 0)
# Used inside the SNOW-V FSM
# ---------------------------------------------------------------------------

# Standard AES S-box
_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

def _xtime(b: int) -> int:
    return ((b << 1) ^ 0x1B) & 0xFF if b & 0x80 else (b << 1) & 0xFF

def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def aes_enc_round(state: list, round_key: list) -> list:
    """One AES-128 encryption round (SubBytes, ShiftRows, MixColumns, AddRoundKey)."""
    # SubBytes
    s = [_SBOX[b] for b in state]
    # ShiftRows
    s = [
        s[0],  s[5],  s[10], s[15],
        s[4],  s[9],  s[14], s[3],
        s[8],  s[13], s[2],  s[7],
        s[12], s[1],  s[6],  s[11],
    ]
    # MixColumns
    out = []
    for col in range(4):
        c = s[col*4:(col+1)*4]
        out += [
            _gmul(c[0],2)^_gmul(c[1],3)^c[2]^c[3],
            c[0]^_gmul(c[1],2)^_gmul(c[2],3)^c[3],
            c[0]^c[1]^_gmul(c[2],2)^_gmul(c[3],3),
            _gmul(c[0],3)^c[1]^c[2]^_gmul(c[3],2),
        ]
    # AddRoundKey
    return [out[i] ^ round_key[i] for i in range(16)]

# ---------------------------------------------------------------------------
# SNOW-V core
# ---------------------------------------------------------------------------

SIGMA = [0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15]

def _bytes_to_u16list(data: bytes) -> list:
    return list(struct.unpack('<' + 'H'*(len(data)//2), data))

def _u16list_to_bytes(lst: list) -> bytes:
    return struct.pack('<' + 'H'*len(lst), *lst)

def _u32_add(a: int, b: int) -> int:
    """Parallel mod-2^32 addition of four 32-bit subwords packed in a 128-bit int."""
    mask = 0xFFFFFFFF
    return (
        (((a >> 96) & mask) + ((b >> 96) & mask) & mask) << 96 |
        (((a >> 64) & mask) + ((b >> 64) & mask) & mask) << 64 |
        (((a >> 32) & mask) + ((b >> 32) & mask) & mask) << 32 |
        ( (a & mask)        + (b & mask)        & mask)
    )

def _bytes16_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def _int_to_bytes16(n: int) -> bytes:
    return n.to_bytes(16, 'big')

def _apply_sigma(state_bytes: bytes) -> bytes:
    return bytes(state_bytes[SIGMA[i]] for i in range(16))

class SnowV:
    def __init__(self, key: bytes, iv: bytes):
        assert len(key) == 32, "Key must be 256 bits (32 bytes)"
        assert len(iv)  == 16, "IV must be 128 bits (16 bytes)"
        self.A = [0] * 16   # LFSR-A, 16 x 16-bit cells
        self.B = [0] * 16   # LFSR-B
        self.R1 = [0] * 16  # FSM registers (as byte lists)
        self.R2 = [0] * 16
        self.R3 = [0] * 16
        self._init(key, iv)

    def _lfsr_update(self):
        for _ in range(8):
            u = (mul_x(self.A[0], ALPHA)
                 ^ self.A[1]
                 ^ mul_x_inv(self.A[8], ALPHA_INV)
                 ^ self.B[0]) & 0xFFFF
            v = (mul_x(self.B[0], BETA)
                 ^ self.B[3]
                 ^ mul_x_inv(self.B[8], BETA_INV)
                 ^ self.A[0]) & 0xFFFF
            for j in range(15):
                self.A[j] = self.A[j+1]
                self.B[j] = self.B[j+1]
            self.A[15] = u
            self.B[15] = v

    def _T1(self) -> bytes:
        """Tap T1: concatenate B[6]..B[1] and A[0] (128 bits)."""
        words = [self.B[6], self.B[5], self.B[4], self.B[3],
                 self.B[2], self.B[1], self.A[0], 0x0000]
        # Pack as little-endian 16-bit words → 16 bytes
        return _u16list_to_bytes(words)

    def _T2(self) -> bytes:
        """Tap T2: A[15]..A[8] (128 bits)."""
        words = self.A[15:7:-1]
        return _u16list_to_bytes(words)

    def _fsm_update(self, t1: bytes, t2: bytes):
        zero_key = [0]*16
        # FSM outputs z before update
        r1_int = _bytes16_to_int(bytes(self.R1))
        t1_int = _bytes16_to_int(t1)
        t2_int = _bytes16_to_int(t2)
        r2_int = _bytes16_to_int(bytes(self.R2))
        r3_int = _bytes16_to_int(bytes(self.R3))

        z_int = (r1_int ^ _u32_add(r2_int, t1_int)) & ((1<<128)-1)
        z = _int_to_bytes16(z_int)

        # Update registers
        new_r3 = aes_enc_round(list(self.R2), zero_key)
        sigma_r1 = list(_apply_sigma(bytes(self.R1)))
        new_r2 = aes_enc_round(sigma_r1, zero_key)

        r1_next_int = _u32_add(r3_int, t2_int) & ((1<<128)-1)
        new_r1 = list(_int_to_bytes16(r1_next_int))

        self.R1 = new_r1
        self.R2 = new_r2
        self.R3 = new_r3
        return z

    def _init(self, key: bytes, iv: bytes):
        k = _bytes_to_u16list(key)   # 16 x u16
        iv_words = _bytes_to_u16list(iv)  # 8 x u16

        # Load key and IV into LFSRs
        for i in range(8):
            self.A[15-i] = k[i]
            self.A[7-i]  = iv_words[i]
            self.B[15-i] = k[8+i]
            self.B[7-i]  = 0

        self.R1 = [0]*16
        self.R2 = [0]*16
        self.R3 = [0]*16

        # 16 initialisation rounds — FSM output XORed back into LFSR-A
        for rnd in range(16):
            t1 = self._T1()
            t2 = self._T2()
            z  = self._fsm_update(t1, t2)

            self._lfsr_update()

            # Mix z into LFSR-A[15]
            z_words = _bytes_to_u16list(z)
            for i in range(8):
                self.A[15-i] ^= z_words[i]  # only lower 8 words used

            # Last 2 rounds: also XOR key into R1
            if rnd >= 14:
                r1_int = _bytes16_to_int(bytes(self.R1))
                k_int  = _bytes16_to_int(key[:16] if rnd == 14 else key[16:])
                new_r1 = _int_to_bytes16(r1_int ^ k_int)
                self.R1 = list(new_r1)

    def keystream_block(self) -> bytes:
        """Generate one 128-bit keystream block."""
        t1 = self._T1()
        t2 = self._T2()
        z  = self._fsm_update(t1, t2)
        self._lfsr_update()
        return z

    def encrypt(self, plaintext: bytes) -> bytes:
        ct = bytearray()
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            ks    = self.keystream_block()
            ct   += bytes(a ^ b for a, b in zip(block, ks[:len(block)]))
        return bytes(ct)


# ---------------------------------------------------------------------------
# CTF challenge generation
# ---------------------------------------------------------------------------

def generate_challenge(flag: str, out_dir: str = "."):
    flag_bytes = flag.encode()

    # Random 256-bit key (this is the secret — do NOT give to contestants)
    key = os.urandom(32)

    # Random 128-bit IV (give this to contestants)
    iv  = os.urandom(16)

    cipher     = SnowV(key, iv)
    ciphertext = cipher.encrypt(flag_bytes)

    # Verify decryption
    cipher2   = SnowV(key, iv)
    plaintext = cipher2.encrypt(ciphertext)
    assert plaintext == flag_bytes, "Self-test failed!"

    iv_hex  = iv.hex()
    ct_hex  = ciphertext.hex()
    key_hex = key.hex()   # keep this safe — only for your answer key

    challenge_text = f"""
╔══════════════════════════════════════════════╗
║         SNOW-SCA CTF Challenge               ║
║   5G Stream Cipher Side-Channel Attack       ║
╚══════════════════════════════════════════════╝

We intercepted a 5G encrypted transmission.
Your goal: recover the secret key via power
side-channel analysis, then decrypt the flag.

Algorithm : SNOW-V (256-bit key, 128-bit IV)
IV        : {iv_hex}
Ciphertext: {ct_hex}

Files provided:
  - power_traces.pcap   (ChipWhisperer captures)
  - challenge.txt       (this file)

Attack steps:
  1. Extract power traces from pcap
  2. Run CPA on the LFSR update function
     targeting the u = mul_x(A[0]) ^ A[1]
                       ^ mul_x_inv(A[8]) ^ B[0]
     operation to recover 2 key byte candidates
  3. Train an LDA classifier on the LSB leakage
     from mul_x_inv() to resolve the ambiguity
  4. Repeat incrementally for all 32 key bytes
  5. Decrypt the ciphertext with the recovered key

Good luck.
"""

    answer_key = f"""SECRET ANSWER KEY — do not distribute
======================================
Key (hex): {key_hex}
IV  (hex): {iv_hex}
CT  (hex): {ct_hex}
Flag     : {flag}
"""

    with open(f"{out_dir}/challenge.txt", "w") as f:
        f.write(challenge_text)

    with open(f"{out_dir}/answer_key.txt", "w") as f:
        f.write(answer_key)

    print(f"[+] Challenge generated")
    print(f"    IV         : {iv_hex}")
    print(f"    Ciphertext : {ct_hex}")
    print(f"    Key (secret): {key_hex}")
    print(f"    Files written: challenge.txt, answer_key.txt")

    return key, iv, ciphertext


if __name__ == "__main__":
    FLAG = "recon{1t_n3v3r_sn0ws_1n_4ndhr4}"
    generate_challenge(FLAG, out_dir=".")

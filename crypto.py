import hashlib
from Crypto.Cipher import AES, DES3, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# ── Constants ─────────────────────────────────────────────────────────────────
SALT_SIZE  = 16
ITERATIONS = 100_000

ALGORITHMS = ["AES-256-CBC", "3DES", "ChaCha20"]


# ── Shared helpers ────────────────────────────────────────────────────────────

def compute_hash(data: bytes) -> str:
    """Return the SHA-256 hex digest of the given bytes."""
    return hashlib.sha256(data).hexdigest()


def verify_integrity(data: bytes, stored_hash: str) -> bool:
    """Return True if the file's current hash matches its stored fingerprint."""
    return compute_hash(data) == stored_hash


def _derive_key(password: str, salt: bytes, key_len: int) -> bytes:
    """Derive a key of key_len bytes from a password using PBKDF2-HMAC-SHA256."""
    return PBKDF2(password, salt, dkLen=key_len, count=ITERATIONS)


# ── AES-256-CBC ───────────────────────────────────────────────────────────────
# Key: 32 bytes | IV: 16 bytes | Padding: PKCS#7

def _aes_encrypt(data: bytes, password: str, salt: bytes):
    key    = _derive_key(password, salt, 32)
    iv     = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size)), iv


def _aes_decrypt(ciphertext: bytes, password: str, salt: bytes, iv: bytes) -> bytes:
    key    = _derive_key(password, salt, 32)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


# ── 3DES ──────────────────────────────────────────────────────────────────────
# Key: 24 bytes | IV: 8 bytes | Padding: PKCS#7
# Legacy algorithm — included for comparison; AES-256 preferred for new data.

def _3des_encrypt(data: bytes, password: str, salt: bytes):
    key    = DES3.adjust_key_parity(_derive_key(password, salt, 24))
    iv     = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(pad(data, DES3.block_size)), iv


def _3des_decrypt(ciphertext: bytes, password: str, salt: bytes, iv: bytes) -> bytes:
    key    = DES3.adjust_key_parity(_derive_key(password, salt, 24))
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size)


# ── ChaCha20 ──────────────────────────────────────────────────────────────────
# Key: 32 bytes | Nonce: 16 bytes | Stream cipher — no padding needed

def _chacha20_encrypt(data: bytes, password: str, salt: bytes):
    key    = _derive_key(password, salt, 32)
    nonce  = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(data), nonce


def _chacha20_decrypt(ciphertext: bytes, password: str,
                      salt: bytes, nonce: bytes) -> bytes:
    key    = _derive_key(password, salt, 32)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)


# ── Public API ────────────────────────────────────────────────────────────────

def encrypt_file(data: bytes, password: str, algorithm: str) -> dict:
    """
    Encrypt raw file bytes with the chosen algorithm.

    Returns a dict with:
        ciphertext    - encrypted bytes
        salt          - 16-byte random salt
        iv            - IV or nonce bytes (length varies by algorithm)
        original_hash - SHA-256 fingerprint of the original plaintext
        algorithm     - algorithm name stored in the bundle
    """
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    original_hash = compute_hash(data)       # hash BEFORE encryption
    salt          = get_random_bytes(SALT_SIZE)

    if algorithm == "AES-256-CBC":
        ciphertext, iv = _aes_encrypt(data, password, salt)
    elif algorithm == "3DES":
        ciphertext, iv = _3des_encrypt(data, password, salt)
    elif algorithm == "ChaCha20":
        ciphertext, iv = _chacha20_encrypt(data, password, salt)

    return {
        "ciphertext":    ciphertext,
        "salt":          salt,
        "iv":            iv,
        "original_hash": original_hash,
        "algorithm":     algorithm,
    }


def decrypt_file(ciphertext: bytes, password: str,
                 salt: bytes, iv: bytes, algorithm: str) -> bytes:
    """
    Decrypt ciphertext using the algorithm recorded in the bundle.
    Raises ValueError on wrong password or corrupted data.
    """
    if algorithm == "AES-256-CBC":
        return _aes_decrypt(ciphertext, password, salt, iv)
    elif algorithm == "3DES":
        return _3des_decrypt(ciphertext, password, salt, iv)
    elif algorithm == "ChaCha20":
        return _chacha20_decrypt(ciphertext, password, salt, iv)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

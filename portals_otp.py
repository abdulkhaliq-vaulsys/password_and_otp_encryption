import base64
import hmac
import struct
import time
import hashlib

TIME_STEP_SECONDS = 30
HMAC_ALGO = hashlib.sha1  # Equivalent to "HmacSHA1" in Java


def generate_code(base32_secret, time_millis=None):
    """Generates a 6-digit TOTP code for the given Base32 secret and time."""
    if time_millis is None:
        time_millis = int(time.time() * 1000)

    # Decode Base32 secret (case-insensitive, padding optional)
    key = base64.b32decode(base32_secret.upper(), casefold=True)

    # Calculate time step (same as Java: timeMillis / 1000 / 30)
    time_window = int(time_millis / 1000 / TIME_STEP_SECONDS)

    # Pack time into 8-byte big-endian buffer
    msg = struct.pack(">Q", time_window)

    # Create HMAC-SHA1 digest
    hmac_hash = hmac.new(key, msg, HMAC_ALGO).digest()

    # Dynamic offset & truncate as per RFC 4226
    offset = hmac_hash[-1] & 0x0F
    truncated_hash = (
        ((hmac_hash[offset] & 0x7F) << 24)
        | ((hmac_hash[offset + 1] & 0xFF) << 16)
        | ((hmac_hash[offset + 2] & 0xFF) << 8)
        | (hmac_hash[offset + 3] & 0xFF)
    )

    # Return 6-digit TOTP
    return truncated_hash % 1_000_000


def main():
    print("🔐 TOTP Debug Utility (Python Version)")
    secret = input("Enter Base32 Secret: ").strip()

    if not secret:
        print("❌ Please enter a valid Base32 secret.")
        return

    now = int(time.time() * 1000)
    prev = generate_code(secret, now - 30_000)
    curr = generate_code(secret, now)
    next_code = generate_code(secret, now + 30_000)

    print("\nGenerated TOTP Codes:")
    print(f"Previous: {prev:06d}")
    print(f"Current : {curr:06d}")
    print(f"Next    : {next_code:06d}")


if __name__ == "__main__":
    main()
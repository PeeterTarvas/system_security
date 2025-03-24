#!/usr/bin/env python3

import random
import sys
import time
from Crypto.Cipher import AES
from datetime import datetime, timedelta



def crack_key(encrypted_file, target_date):
    target_timestamp = int(target_date.timestamp())

    # Try seeds for the entire day (in seconds)
    for seconds_offset in range(0, 24 * 60 * 60):
        t = target_timestamp + seconds_offset
        random.seed(int(t))
        candidate_key = random.randbytes(16)

        # Read the encrypted file
        with open(encrypted_file, 'rb') as f:
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        # Try to decrypt
        try:
            aes = AES.new(candidate_key, AES.MODE_GCM, nonce=nonce)
            plaintext = aes.decrypt_and_verify(ciphertext, tag)
            print(f"Found correct key at timestamp {t}, which is {datetime.fromtimestamp(t)}")
            return plaintext
        except (ValueError, KeyError):
            continue

    return None  # Failed to find the key

if __name__ == '__main__':
    today = datetime.now()
    last_monday = today - timedelta(days=today.weekday())
    last_monday = datetime(last_monday.year, last_monday.month, last_monday.day)
    print(crack_key("ciphertext.bin", last_monday))
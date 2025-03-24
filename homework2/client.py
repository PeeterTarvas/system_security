#!/usr/bin/env python3
import socket
import sys
import logging
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


from ICMPPacket import ICMPPacket

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s,%(msecs)03d [ecc-client - %(levelname)s] [%(filename)s:%(lineno)d]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('ecc-client')


KEY = b'ThisIsA32ByteKeyForAES256Encrypt'


def encrypt_message(plaintext):
    try:
        plaintext = plaintext.encode('utf-8')
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(KEY)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return nonce + ciphertext
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return None


def send_message(destination_ip, message):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)

        encrypted_data = encrypt_message(message)

        if encrypted_data:
            icmp_packet = ICMPPacket(data=encrypted_data)
            packet = icmp_packet.pack()

            sock.sendto(packet, (destination_ip, 0))
            logger.info("Sent packet")

            # Close socket
            sock.close()
            return True
        else:
            logger.error("Failed to encrypt message")
            return False

    except socket.error as e:
        logger.error(f"Socket error: {e}")
        if e.errno == 1:
            logger.error("Operation not permitted - You need to run this as root/sudo")
        return False

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False


def main():
    if len(sys.argv) < 2:
        logger.error("Usage: sudo python3 client.py <destination_ip>")
        sys.exit(1)

    destination_ip = sys.argv[1]
    logger.info("Starting up ecc-client.")

    try:
        while True:
            message = input("Enter the message: ")
            if message:
                send_message(destination_ip, message)
            else:
                logger.info("Empty message, not sending")

    except KeyboardInterrupt:
        logger.info("Client shutting down")
        sys.exit(0)


if __name__ == "__main__":
    main()
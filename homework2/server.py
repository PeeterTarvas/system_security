import socket
import sys
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


from ICMPPacket import ICMPPacket

KEY = b'ThisIsA32ByteKeyForAES256Encrypt'


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s,%(msecs)03d [ecc-server - %(levelname)s] [%(filename)s:%(lineno)d]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('ecc-server')

def decrypt_message(encrypted_data):
    try:
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(KEY)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.warning(f"Decryption failed or message integrity compromised: {e}")
        return None



def main():
    logger.info("Starting up ecc-server.")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        logger.info("Created socket. Start listening.")

        while True:
            packet, addr = sock.recvfrom(65536)

            try:
                icmp_packet = ICMPPacket(packet=packet)
            except ValueError as e:
                logger.warning(f"Invalid checksum: {e}")
                continue

            if icmp_packet.type == 47:
                if icmp_packet.data:
                    decrypted_data = decrypt_message(icmp_packet.data)
                    if decrypted_data:
                        logger.info(f"Received plaintext: '{decrypted_data}'")
                    else:
                        logger.warning("Received invalid encrypted data")

    except socket.error as e:
        logger.error(f"Socket error: {e}")
        if e.errno == 1:
            logger.error("Operation not permitted - You need to run this as root/sudo")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Server shutting down")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
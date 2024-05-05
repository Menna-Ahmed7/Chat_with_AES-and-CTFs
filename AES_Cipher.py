from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import hashlib

def generate_key(secret_key):
    #  h = hashlib.sha1(str(secret_key).encode('utf-8'))
    # hex_digest = h.hexdigest()
    return hashlib.sha256(str(secret_key).encode()).digest()

def encrypt(message, key):
    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad the message to ensure it's a multiple of the block size
    padded_message = pad(message.encode('utf-8'), AES.block_size)

    # Encrypt the padded message
    cipher_text = cipher.encrypt(padded_message)
    return cipher_text

def decrypt(cipher_text, key):
    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the cipher text
    decrypted_message = cipher.decrypt(cipher_text)

    # Unpad the decrypted message
    unpadded_message = unpad(decrypted_message, AES.block_size)

    return unpadded_message.decode('utf-8')
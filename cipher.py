from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64



def aes_encrypt(plaintext, key):
    # Generate a random initialization vector (IV)
    iv = get_random_bytes(AES.block_size)
    # Initialize AES cipher in CBC mode with the provided key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad the plaintext to match the block size
    padded_plaintext = pad(plaintext.encode('ascii'), AES.block_size)
    # Encrypt the plaintext
    ciphertext = cipher.encrypt(padded_plaintext)
    # Encode ciphertext and IV in base64 for better representation
    return base64.b64encode(iv + ciphertext).decode('ascii')

def aes_decrypt(ciphertext, key):
    # Decode the base64 encoded ciphertext
    ciphertext = base64.b64decode(ciphertext)
    # Extract the IV from the ciphertext
    iv = ciphertext[:AES.block_size]
    # Initialize AES cipher in CBC mode with the provided key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt the ciphertext
    decrypted_padded_plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    # Unpad the decrypted plaintext
    plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
    return plaintext.decode('ascii')


def post(message, client, key):
    encrypted_message = aes_encrypt(message, key)
    encrypted_message_in_byte = encrypted_message.encode('ascii')
    client.send(encrypted_message_in_byte)
    # return(encrypted_message_in_byte)
    
def get(client, key):
    encrypted_message_in_byte = client.recv(1024)
    encrypted_message = encrypted_message_in_byte.decode('ascii')
    message = aes_decrypt(encrypted_message, key)
    return message





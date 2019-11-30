import time
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

''' PBKDF KEY DERIVATION
password_provided = "password" # This is input in the form of a string
password = password_provided.encode() # Convert to type bytes
salt = b'00000000'
#print(salt)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=10000,
    backend=default_backend()
)
key256 = kdf.derive(password)
print(key256)
'''

f = open(sys.argv[1], "rb")
in_string = f.read()

input = base64.encodebytes(in_string)                                           # convert in base64 bytes
in_size = len(input)
plaintext_len = ((in_size//16) + 1) * 16                                        # length for pad
input = input.ljust(plaintext_len, bytes('0', 'utf-8'))                         # add padding


key256 = get_random_bytes(32)
print(key256)
iv128 = get_random_bytes(AES.block_size)
print(iv128)


print("\n********************************************* Cipher Algorithm: AES with CBC mode *********************************************\n")

print("+++++++++++++++++++++  Libraries: PyCryptodome");
print("ENCRYPTING", end = '');
aes = AES.new(key256, AES.MODE_CBC, iv128)
start = time.time()
ciphertext = aes.encrypt(input)
end = time.time()
enc_time = end-start
print(" Time ===> " + str(enc_time));

print("DECRYPTING", end = '');
aes = AES.new(key256, AES.MODE_CBC, iv128)
start = time.time()
plaintext = aes.decrypt(ciphertext)
end = time.time()
dec_time = end-start
print(" Time ===> " + str(dec_time));
print("	SPEED RATIO ==========> " + str(enc_time/dec_time) + '\n');


print("+++++++++++++++++++++  Libraries: Cryptography");
backend = default_backend()
aes = Cipher(algorithms.AES(key256), modes.CBC(iv128), backend=backend)

print("ENCRYPTING", end = '');
start = time.time()
encryptor = aes.encryptor()
ciphertext = encryptor.update(input) + encryptor.finalize()
end = time.time()
enc_time = end-start
print(" Time ===> " + str(enc_time));

print("DECRYPTING", end = '');
start = time.time()
decryptor = aes.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
end = time.time()
dec_time = end-start
print(" Time ===> " + str(dec_time));
print("	SPEED RATIO ==========> " + str(enc_time/dec_time));

print(ciphertext)
print('\n')
print(base64.decodebytes(plaintext))

# OUTPUT CHECKING
#f = open("plaintext.jpg", "wb")
#f.write(plaintext)
#f.close()

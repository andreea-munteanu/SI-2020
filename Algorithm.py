from cryptography.fernet import Fernet
import random

# saving the generated key
secret_key = None

# checked; works
def get_random_bytes(size) :  # 128
    bytestring = bytearray(random.getrandbits(8) for _ in range(size))
    return bytestring


# change string to bits
# checked; works
def char_to_bits(text_str) :
    res = ''.join(format(ord(i), 'b') for i in text_str)
    return res

# checked; works
def unpadding(message):
    return message.decode('utf-8').rstrip('\x00')

# function to generate key
# checked; works
def generate_key() :
    global secret_key
    key = Fernet.generate_key()
    # ### just to check: ###
    # if key:
    #     print("key is ", key)
    # else:
    #     print("no key generated")
    with open("secret_key.txt", "wb") as key_file :
        key_file.write(key)
    secret_key = key


# read key from file
def load_key() :
    return open("secret_key.txt", "rb").read()
    # return secret_key


# encrypt message
def encrypt_message(message, key) :
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message


def decrypt_message(encrypted_message, key) :
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()
    # with open("secret_key.txt", "rb") as file:
    #     # read the encrypted data
    #     encrypted_data = file.read()
    # # # decrypt data
    # # # decrypted_data = f.decrypt(encrypted_data)
    # # # write the original file
    # # with open("secret_key.txt", "wb") as file:
    # #     file.write(decrypted_data)


# random bytes of size 128
def generate_IV() :
    return get_random_bytes(128)


# apply xor
def xor(text_a, text_b) :
    return text_a ^ text_b

# following schemes at: https://profs.info.uaic.ro/~liliana.cojocaru/Laborator2.pdf

def CBC_mode_encryption(message, IV) :
    plaintext = []
    CIPHERTEXT = []
    ENCODED = []
    current_byte = 0
    key = load_key()
    for bit in message :
        # we form each byte separately
        if len(plaintext) != 0 and len(plaintext) % 8 == 0 :
            # plaintextul se formeaza corect
            plaintext = ''.join(map(str, plaintext))
            ENCODED.append(plaintext)
            if current_byte == 0 :
                block_cipher_encryption = xor(plaintext, IV)
                ciphertext = encrypt_message(block_cipher_encryption, key)
                CIPHERTEXT = ciphertext
                # print(ciphertext)
            else :
                block_cipher_encryption = xor(plaintext, CIPHERTEXT)
                ciphertext = encrypt_message(block_cipher_encryption, key)
                CIPHERTEXT = ciphertext
                # print(ciphertext)
            current_byte += 1
            plaintext = []
        else :
            plaintext.append(bit)
    return ENCODED


# reverse of CBC_mode_encryption
def CBC_mode_decryption(message, IV) :
    decrypted_message = []
    key = load_key()
    plaintext = []
    ciphertext = []
    CIPHERTEXT = ciphertext
    current_byte = 0
    for bit in message :
        if len(ciphertext) != 0 and len(ciphertext) % 8 == 0 :
            # plaintextul se formeaza corect
            ciphertext = ''.join(map(str, ciphertext))
            if current_byte == 0:
                block_cipher_encryption = decrypt_message(ciphertext, key)
                plaintext = xor(IV, block_cipher_encryption)
                CIPHERTEXT = ciphertext
            else:
                block_cipher_encryption = decrypt_message(ciphertext, key)
                plaintext = xor(CIPHERTEXT, plaintext)
                CIPHERTEXT = ciphertext
                decrypted_message.append(plaintext)
            current_byte += 1
            ciphertext = []
    return decrypted_message


def OFB_mode_encryption(message, IV) :
    plaintext = []
    key = load_key()
    BLOCK_CIPHER_ENCRYPTION = []
    current_byte = 0
    CIPHERTEXT_FINAL = []
    for bit in message:
        if len(plaintext) != 0 and len(plaintext) % 8 == 0 :
            plaintext = ''.join(map(str, plaintext))
            CIPHERTEXT_FINAL.append(ciphertext)
            if current_byte == 0:
                block_cipher_encryption = encrypt_message(IV, key)
                ciphertext = xor(block_cipher_encryption, plaintext)
                BLOCK_CIPHER_ENCRYPTION = block_cipher_encryption
            else:
                block_cipher_encryption = xor(BLOCK_CIPHER_ENCRYPTION, key)
                ciphertext = xor(block_cipher_encryption, plaintext)
                BLOCK_CIPHER_ENCRYPTION = block_cipher_encryption
            current_byte += 1
            plaintext = []
        else :
            plaintext.append(bit)
    return CIPHERTEXT_FINAL


# reverse of OFB_mode_encryption
def OFB_mode_decryption(message, IV) :
    decrypted_message = []
    key = load_key()
    plaintext = []
    ciphertext = []
    BLOCK_CIPHER_ENCRYPTION = None
    current_byte = 0
    for bit in message :
        if len(ciphertext) != 0 and len(ciphertext) % 8 == 0 :
            # plaintextul se formeaza corect
            ciphertext = ''.join(map(str, ciphertext))
            decrypted_message.append(plaintext)
            if current_byte == 0:
                block_cipher_encryption = decrypt_message(IV, key)
                BLOCK_CIPHER_ENCRYPTION = block_cipher_encryption
                plaintext = xor(ciphertext, block_cipher_encryption)
                CIPHERTEXT = ciphertext
            else:
                block_cipher_encryption = decrypt_message(BLOCK_CIPHER_ENCRYPTION, key)
                BLOCK_CIPHER_ENCRYPTION = block_cipher_encryption
                plaintext = xor(block_cipher_encryption, ciphertext)
                decrypted_message.append(plaintext)
            current_byte += 1
            ciphertext = []
        else:
            plaintext.append(bit)
    return decrypted_message

# establishing communication
def communication(message, type) :
    generate_key()
    key = load_key()
    IV = generate_IV()
    if type == 'CBC':
        print("Communication established")
        message = encrypt_message(message, key)
        print("CBC encrypted message is: ", CBC_mode_encryption(message, IV))
        print("CBC decoded message is: ", CBC_mode_decryption(message, IV))
        print("End of communication")
    elif type == 'OFB':
        print("Communication established")
        message = encrypt_message(message, key)
        print("OFB encrypted message is: ", OFB_mode_encryption(message, IV))
        print("OFB decoded message is: ", OFB_mode_decryption(message, IV))
        print("End of communication")
    else:
        print("Error. Wrong type!")


type = {'CBC', 'OFB'}


def main() :
    message = "this is the message to be encrypted and decrypted"
    your_type = input()
    while your_type != 'CBC' and your_type != 'OFB':
        print("Wrong type! Insert valid type: ")
        your_type = input()
    communication(message, your_type)

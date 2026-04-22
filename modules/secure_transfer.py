from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_data, key):
    f = Fernet(key)
    return f.encrypt(file_data)

def decrypt_file(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data)
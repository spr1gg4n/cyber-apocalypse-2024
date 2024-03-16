from Crypto.Cipher import AES
import base64

def decrypt_string(encrypted_base64, key):
    full_data = base64.b64decode(encrypted_base64)
    
    iv = full_data[:AES.block_size]
    encrypted_message = full_data[AES.block_size:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    decrypted_bytes = cipher.decrypt(encrypted_message)
    
    pad = decrypted_bytes[-1]
    decrypted_bytes = decrypted_bytes[:-pad]
    
    return decrypted_bytes.decode('utf-8')

# Read AES key from file and assign it to aes_key_base64
with open("aes_key.txt", "rb") as file:
    aes_key_base64 = file.read().decode("utf-8")
    aes_key = base64.b64decode(aes_key_base64)

# Read encrypted data from file and assign it to encrypted_base64
with open("encrypted_data.txt", "rb") as file:
    encrypted_base64 = file.read().decode("utf-8")

decrypted_text = decrypt_string(encrypted_base64, aes_key)
print("Decrypted text:", decrypted_text)

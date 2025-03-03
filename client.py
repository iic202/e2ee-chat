import socket
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Shared secret key (must be 16, 24, or 32 bytes)
SECRET_KEY = b"thisisverysecret"  # Exactly 16 bytes

# Function to pad messages to fit AES block size (16 bytes)
def pad(msg):
    if isinstance(msg, str):  # Convert str to bytes if needed
        msg = msg.encode()
    return msg + b" " * (16 - len(msg) % 16)

# Function to encrypt a message
def encrypt_message(message):
    iv = get_random_bytes(16)  # Generate a random IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message))
    return base64.b64encode(iv + encrypted)  # Send IV + encrypted data

# Function to decrypt a message
def decrypt_message(encrypted_msg):
    data = base64.b64decode(encrypted_msg)  # Decode from Base64
    iv = data[:16]  # First 16 bytes = IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    return cipher.decrypt(data[16:]).rstrip()  # Decrypt rest of the data


# Setup client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 12345))  # Connect to server

while True:
    message = input("You: ")
    client.send(encrypt_message(message.encode()))  # Encrypt and send message

    encrypted_data = client.recv(1024)  # Receive encrypted reply
    decrypted_message = decrypt_message(encrypted_data).decode()
    print(f"Server: {decrypted_message}")

client.close()

if __name__ == "__main__":
    pass
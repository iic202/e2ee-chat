# End-to-end-encryption chat 

## Overview
This project demonstrates how to encrypt and decrypt messages using the **AES (Advanced Encryption Standard)** algorithm in **CBC (Cipher Block Chaining) mode** with a **16-byte secret key**.

## How It Works
### 1. **Secret Key**
A **16, 24, or 32-byte key** is required to use AES encryption. In this project, a **16-byte key** is used:
```python
SECRET_KEY = b"thisisverysecret"  # 16 bytes
```

### 2. **Padding the Message**
AES requires input messages to be a **multiple of 16 bytes**. If a message is too short, it is **padded** with spaces:
```python
def pad(msg):
    if isinstance(msg, str):
        msg = msg.encode()  # Convert string to bytes
    return msg + b" " * (16 - len(msg) % 16) # Return message with padding 
```

### 3. **Encryption Process**
1. Generate a **random IV (Initialization Vector)** of **16 bytes**.
2. Create an **AES cipher object** using **CBC mode**.
3. Encrypt the **padded message**.
4. **Prepend** the IV to the encrypted data.
5. Encode the result using **Base64** for easy storage & transmission.

```python
def encrypt_message(message):
    iv = get_random_bytes(16)  # Generate IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message))
    return base64.b64encode(iv + encrypted)  # Encode IV + encrypted data
```

### 4. **Decryption Process**
1. **Decode** the Base64-encoded data.
2. Extract the **IV** (first 16 bytes).
3. Recreate the **AES cipher** using the **same key and IV**.
4. Decrypt the remaining bytes.
5. **Remove padding spaces** to retrieve the original message.

```python
def decrypt_message(encrypted_msg):
    data = base64.b64decode(encrypted_msg)  # Decode from Base64
    iv = data[:16]  # Extract IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    return cipher.decrypt(data[16:]).rstrip()  # Remove padding spaces
```

## Notes
- **Never hardcode the secret key** in real applications.
- Consider using **PKCS7 padding** instead of spaces for better security.

## Requirements
Install dependencies using:
```sh
pip install pycryptodome
```

## Overview of User Interface
The user graphical user interface was done with tkinter which is already integrated with python. The user interface is shown underneath, 
it features a text box to enter the messages, a display box to show the messages sent and received and a status message to show the status of the connection or any errors that may occur.

![GUI](pictures/overview_gui.png)
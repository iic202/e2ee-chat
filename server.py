import socket
import base64
import threading
import tkinter as tk
from tkinter import scrolledtext
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

class ServerGui:
    def __init__(self, root):
        self.root = root
        self.root.title("E2EE Server")
        self.root.geometry("575x350") # Window dimensions
        self.root.resizable(False, False)
        
        # Create UI elements
        self.chat_display = scrolledtext.ScrolledText(root, width=70, height=15)
        self.chat_display.grid(row=0, column=0, padx=10, pady=10, columnspan=2)
        self.chat_display.config(state=tk.DISABLED)
        
        self.msg_entry = tk.Entry(root, width=50)
        self.msg_entry.grid(row=1, column=0, padx=10, pady=10)
        self.msg_entry.bind('<Return>', self.send_message)
        
        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=10, pady=10)
        
        self.status_label = tk.Label(root, text="Waiting for connection...")
        self.status_label.grid(row=2, column=0, columnspan=2)
        
        # Server setup
        self.server = None
        self.client = None
        self.client_address = None
        
        # Start server in a separate thread
        self.server_thread = threading.Thread(target=self.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()
    
    def update_chat_display(self, message, sender="Client"):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"[{sender}] {message}\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 12345))
        self.server.listen(1)
        
        self.status_label.config(text="Server is listening on 127.0.0.1 on port 12345...")
        
        self.client, self.client_address = self.server.accept()
        self.status_label.config(text=f"Connected with {self.client_address[0]}")
        
        # Start a thread to receive messages
        threading.Thread(target=self.receive_messages).daemon = True
        threading.Thread(target=self.receive_messages).start()
    
    def receive_messages(self):
        try:
            while True:
                encrypted_data = self.client.recv(1024)
                if not encrypted_data:
                    break
                
                decrypted_message = decrypt_message(encrypted_data).decode()
                self.root.after(0, lambda msg=decrypted_message: self.update_chat_display(msg))
        except:
            self.status_label.config(text="Connection closed")
        finally:
            self.client.close()
    
    def send_message(self, event=None):
        message = self.msg_entry.get()
        if message:
            if self.client:
                try:
                    self.update_chat_display(message, "You")
                    self.client.send(encrypt_message(message))
                    self.msg_entry.delete(0, tk.END)
                except:
                    self.status_label.config(text="Error sending message")
            else:
                self.status_label.config(text="No client connected")

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGui(root)
    root.mainloop()

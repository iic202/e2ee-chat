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

def encrypt_message(message):
    iv = get_random_bytes(16)  # Generate a random IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message))
    return base64.b64encode(iv + encrypted)  # Send IV + encrypted data

def decrypt_message(encrypted_msg):
    data = base64.b64decode(encrypted_msg)  # Decode from Base64
    iv = data[:16]  # First 16 bytes = IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    return cipher.decrypt(data[16:]).rstrip()  # Decrypt rest of the data

class ClientGui:
    def __init__(self, root):
        self.root = root
        self.root.title("E2EE Client")
        self.root.geometry("575x350") # Window dimensions
        self.root.resizable(False, False) # No window resizing
        
        # Create chat display
        self.chat_display = scrolledtext.ScrolledText(root, width=70, height=15)
        self.chat_display.grid(row=0, column=0, padx=10, pady=10, columnspan=2)
        self.chat_display.config(state=tk.DISABLED)
        
        # Create message entry
        self.msg_entry = tk.Entry(root, width=50)
        self.msg_entry.grid(row=1, column=0, padx=10, pady=10)
        self.msg_entry.bind('<Return>', self.send_message)
        
        # Create send button
        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=10, pady=10)
        
        # Create status label
        self.status_label = tk.Label(root, text="Not connected")
        self.status_label.grid(row=2, column=0, columnspan=2)
        
        # Client socket
        self.client = None
        
        # Start client in a separate thread
        self.client_thread = threading.Thread(target=self.connect_to_server)
        self.client_thread.daemon = True
        self.client_thread.start()
    
    def update_chat_display(self, message, sender="Server"):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"[{sender}] {message}\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def connect_to_server(self):
        try:
            # TCP socket connection
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            self.client.connect(("127.0.0.1", 12345))
            self.status_label.config(text="Connected to server")
            
            # Start a thread to receive messages
            threading.Thread(target=self.receive_messages).daemon = True
            threading.Thread(target=self.receive_messages).start()
        except Exception as e:
            self.status_label.config(text=f"Connection error: {str(e)}")
    
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
                self.status_label.config(text="Not connected to server")

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGui(root)
    root.mainloop()


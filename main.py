import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import qrcode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64
import cv2  # QR kod çözme için opencv

class QRSteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("QR Code Steganography Tool")
        self.root.geometry("475x600")
        self.root.configure(bg="#f0f0f0")

        self.setup_ui()

    def setup_ui(self):
        # Frame for QR Code Display
        self.qr_frame = ttk.LabelFrame(self.root, text="QR Code Preview", padding=10)
        self.qr_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.qr_label = ttk.Label(self.qr_frame, text="QR Code will appear here")
        self.qr_label.pack(expand=True)

        # Frame for Controls
        self.control_frame = ttk.LabelFrame(self.root, text="Controls", padding=10)
        self.control_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        # Message Entry
        ttk.Label(self.control_frame, text="Message:").grid(row=0, column=0, sticky="w")
        self.message_entry = ttk.Entry(self.control_frame, width=50)
        self.message_entry.grid(row=0, column=1, padx=5, pady=5)

        # Password Entry
        ttk.Label(self.control_frame, text="Password:").grid(row=1, column=0, sticky="w")
        self.password_entry = ttk.Entry(self.control_frame, width=50, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        # Buttons
        ttk.Button(self.control_frame, text="Generate QR Code", command=self.generate_qr).grid(row=2, column=0, pady=10)
        ttk.Button(self.control_frame, text="Decode QR Code", command=self.decode_qr).grid(row=2, column=1, pady=10)
        ttk.Button(self.control_frame, text="Save QR Code", command=self.save_qr).grid(row=3, column=0, pady=10)
        ttk.Button(self.control_frame, text="Upload QR Code", command=self.upload_qr).grid(row=3, column=1, pady=10)

    def generate_qr(self):
        message = self.message_entry.get()
        password = self.password_entry.get()

        if not message or not password:
            messagebox.showerror("Error", "Message and password are required!")
            return

        encrypted_message = self.encrypt_message(message, password)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(encrypted_message)
        qr.make(fit=True)

        self.img = qr.make_image(fill='black', back_color='white')
        self.img = self.img.resize((300, 300), Image.Resampling.LANCZOS)  # ANTIALIAS yerine LANCZOS kullanıldı
        self.qr_image = ImageTk.PhotoImage(self.img)
        self.qr_label.config(image=self.qr_image)

    def decode_qr(self):
        password = self.password_entry.get()

        if not hasattr(self, 'uploaded_image'):
            messagebox.showerror("Error", "Please upload a QR code first!")
            return

        if not password:
            messagebox.showerror("Error", "Password is required!")
            return

        try:
            # QR kodunu çöz
            image_path = "temp_qr.png"  # Geçici dosya olarak kaydet
            self.uploaded_image.save(image_path)

            # OpenCV ile QR kodunu oku
            image = cv2.imread(image_path)
            detector = cv2.QRCodeDetector()
            encrypted_message, _, _ = detector.detectAndDecode(image)

            if not encrypted_message:
                messagebox.showerror("Error", "No QR code found in the image!")
                return

            decrypted_message = self.decrypt_message(encrypted_message, password)
            messagebox.showinfo("Decoded Message", decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decode QR code or incorrect password! Error: {e}")

    def save_qr(self):
        if not hasattr(self, 'img'):
            messagebox.showerror("Error", "No QR code to save!")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if file_path:
            self.img.save(file_path)  # PIL.Image nesnesini kaydet

    def upload_qr(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if file_path:
            self.uploaded_image = Image.open(file_path)
            self.uploaded_image = self.uploaded_image.resize((300, 300), Image.Resampling.LANCZOS)  # ANTIALIAS yerine LANCZOS kullanıldı
            self.qr_image = ImageTk.PhotoImage(self.uploaded_image)
            self.qr_label.config(image=self.qr_image)

    def encrypt_message(self, message, password):
        # Derive a 32-byte key from the password
        key = password.ljust(32)[:32].encode()
        iv = os.urandom(16)  # Generate a random IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the message to be a multiple of 16 bytes
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()

        # Encrypt the padded message
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_message).decode('utf-8')

    def decrypt_message(self, encrypted_message, password):
        # Derive a 32-byte key from the password
        key = password.ljust(32)[:32].encode()
        encrypted_message = base64.b64decode(encrypted_message.encode('utf-8'))
        iv = encrypted_message[:16]
        encrypted_message = encrypted_message[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the message
        padded_data = decryptor.update(encrypted_message) + decryptor.finalize()

        # Unpad the decrypted message
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        message = unpadder.update(padded_data) + unpadder.finalize()
        return message.decode('utf-8')

if __name__ == "__main__":
    root = tk.Tk()
    app = QRSteganographyApp(root)
    root.mainloop()
# QR Code Steganography Tool

This is a Python application that allows you to generate and decode QR codes with encrypted messages using steganography. The application uses the Tkinter library for the GUI, the `qrcode` library for generating QR codes, and the `cryptography` library for encryption and decryption.

## Features

- Generate QR codes with encrypted messages.
- Decode QR codes to retrieve encrypted messages.
- Save generated QR codes as image files.
- Upload QR codes for decoding.

## Requirements

- Python 3.x
- Tkinter
- Pillow
- qrcode
- cryptography
- OpenCV

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/qr-steganography-tool.git
    cd qr-steganography-tool
    ```

2. Install the required packages:

    ```sh
    pip install -r requirements.txt
    ```

    Create a `requirements.txt` file with the following contents:

    ```txt
    pillow
    qrcode
    cryptography
    opencv-python
    ```

## Usage

1. Run the application:

    ```sh
    python main.py
    ```

2. Use the GUI to generate and decode QR codes:
    - Enter a message and password, then click "Generate QR Code" to create a QR code with the encrypted message.
    - Click "Save QR Code" to save the generated QR code as an image file.
    - Click "Upload QR Code" to upload an existing QR code image for decoding.
    - Enter the password used for encryption, then click "Decode QR Code" to retrieve the original message.

## ScreenShots

<img width="400" alt="pg11" src="https://github.com/user-attachments/assets/bb89f6e6-7ad2-4030-9c76-99797a4e4ce1" />
<img width="400" alt="pg11" src="https://github.com/user-attachments/assets/0cc0b8a7-676a-4458-b5f9-0941f7c9d4ff" />

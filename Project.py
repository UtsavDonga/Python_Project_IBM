import sys
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QLineEdit, QFileDialog, QVBoxLayout, QMessageBox
from PIL import Image
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

class SteganographyApp(QWidget):
    def _init_(self):
        super()._init_()

        # Variables
        self.image_path = None
        self.message = None
        self.encryption_key = None

        # Create GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Image Input
        self.image_label = QLabel("Select Image:", self)
        self.browse_button = QPushButton("Browse", self)
        self.browse_button.clicked.connect(self.browse_image)

        # Message Input
        self.message_label = QLabel("Enter Message:", self)
        self.message_entry = QLineEdit(self)

        # Encryption Key Input
        self.encryption_label = QLabel("Enter Encryption Key:", self)
        self.encryption_entry = QLineEdit(self)
        self.encryption_entry.setEchoMode(QLineEdit.Password)

        # Buttons
        self.encrypt_button = QPushButton("Encrypt", self)
        self.encrypt_button.clicked.connect(self.encrypt_image)
        self.decrypt_button = QPushButton("Decrypt", self)
        self.decrypt_button.clicked.connect(self.decrypt_image)

        # Layout
        layout = QVBoxLayout(self)
        layout.addWidget(self.image_label)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.message_label)
        layout.addWidget(self.message_entry)
        layout.addWidget(self.encryption_label)
        layout.addWidget(self.encryption_entry)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)

        self.setLayout(layout)

    def browse_image(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select Image", "", "Image files (*.png;*.jpg;*.jpeg)")

        if file_path:
            self.image_path = file_path

    def derive_key(self, user_key):
        # Use PBKDF2 for key derivation
        salt = b'some_salt'  # You may want to use a random salt for more security
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,  # You can adjust the number of iterations based on your security needs
            salt=salt,
            length=32  # The desired length of the derived key
        )
        key = kdf.derive(user_key.encode())
        return key


    import base64

# ... (your existing code)

    def encrypt_image(self):
        if not all([self.image_path, self.message_entry.text(), self.encryption_entry.text()]):
            QMessageBox.critical(self, "Error", "Please fill in all fields.")
            return

        try:
            # Open image
            img = Image.open(self.image_path)

            # Derive a key of the correct size
            key = self.derive_key(self.encryption_entry.text())

            # Encrypt message with PKCS7 padding
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_message = padder.update(self.message_entry.text().encode()) + padder.finalize()

            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

            # Convert encrypted message to base64 for embedding
            encrypted_base64 = base64.b64encode(encrypted_message)

            # Hide message in image
            flattened_image = list(img.getdata())

            # Embed base64-encoded encrypted message into the least significant bits of the image pixels
            for i in range(len(encrypted_base64)):
                pixel_value = flattened_image[i]
                new_pixel_value = (pixel_value[0], pixel_value[1], pixel_value[2] ^ encrypted_base64[i])
                flattened_image[i] = new_pixel_value

            img.putdata(flattened_image)

            # Save encrypted image
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted Image", "", "PNG files (*.png)")
            if save_path:
                img.save(save_path)
                QMessageBox.information(self, "Success", "Encryption successful. Image saved.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def decrypt_image(self):
        if not all([self.image_path, self.encryption_entry.text()]):
            QMessageBox.critical(self, "Error", "Please select an encrypted image and enter the encryption key.")
            return

        try:
            # Open encrypted image
            img = Image.open(self.image_path)

            # Derive a key of the correct size
            key = self.derive_key(self.encryption_entry.text())

            # Extract base64-encoded encrypted message from the least significant bits of the image pixels
            flattened_image = list(img.getdata())
            encrypted_base64 = bytes([(pixel_value[2] ^ 0) for pixel_value in flattened_image])

            # Decode base64
            encrypted_message = base64.b64decode(encrypted_base64)

            # Decrypt message
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

            # Remove PKCS7 padding
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

            # Display or process the decrypted message as needed
            print("Decrypted Message:", decrypted_message.decode('utf-8'))

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")





        if not all([self.image_path, self.encryption_entry.text()]):
            QMessageBox.critical(self, "Error", "Please select an encrypted image and enter the encryption key.")
            return

        try:
            # Open encrypted image
            img = Image.open(self.image_path)

            # Derive a key of the correct size
            key = self.derive_key(self.encryption_entry.text())

            # Extract base64-encoded encrypted message from the least significant bits of the image pixels
            flattened_image = list(img.getdata())
            encrypted_base64 = bytes([(pixel_value[2] ^ 0) for pixel_value in flattened_image])

            # Decode base64
            encrypted_message = base64.b64decode(encrypted_base64)

            # Decrypt message
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

            # Remove PKCS7 padding
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

            # Display or process the decrypted message as needed
            print("Decrypted Message:", decrypted_message.decode('utf-8'))

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

            if not all([self.image_path, self.encryption_entry.text()]):
                QMessageBox.critical(self, "Error", "Please select an encrypted image and enter the encryption key.")
                return

            try:
                # Open encrypted image
                img = Image.open(self.image_path)

                # Derive a key of the correct size
                key = self.derive_key(self.encryption_entry.text())

                # Decrypt message
                cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_padded_message = decryptor.update(img.tobytes()) + decryptor.finalize()

                # Remove PKCS7 padding
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

                # Display or process the decrypted message as needed
                print("Decrypted Message:", decrypted_message.decode('utf-8'))

            except Exception as e:
                QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

                if not all([self.image_path, self.encryption_entry.text()]):
                    QMessageBox.critical(self, "Error", "Please select an encrypted image and enter the encryption key.")
                    return

                try:
                    # Open encrypted image
                    img = Image.open(self.image_path)

                    # Derive a key of the correct size
                    key = self.derive_key(self.encryption_entry.text())

                    # Decrypt message
                    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
                    decryptor = cipher.decryptor()
                    decrypted_padded_message = decryptor.update(img.tobytes()) + decryptor.finalize()

                    # Remove PKCS7 padding
                    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

                    # Display or process the decrypted message as needed
                    print("Decrypted Message:", decrypted_message.decode('utf-8'))

                except Exception as e:
                    QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")



if _name_ == "_main_":
    app = QApplication(sys.argv)
    steganography_app = SteganographyApp()
    steganography_app.show()
    sys.exit(app.exec_())

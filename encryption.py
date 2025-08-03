from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os


class HybirdEncryption:
    def __init__(self):
        load_dotenv()

        def get_key_from_env(var):
            key = os.environ.get(var)
            if key:
                # Replace literal '\n' with actual newlines and encode to bytes
                return key.replace("\\n", "\n").encode("utf-8")
            return None

        self.own_pem_private_key = (
            get_key_from_env("OWN_PEM_PRIVATE_KEY")
            if os.environ.get("OWN_PEM_PRIVATE_KEY")
            else self._generate_keys()[0]
        )
        self.own_pem_public_key = (
            get_key_from_env("OWN_PEM_PUBLIC_KEY")
            if os.environ.get("OWN_PEM_PUBLIC_KEY")
            else self._generate_keys()[1]
        )

        self.encrypted_message = None
        self.encrypted_symmetric_key_to_send_to_recipient = None
        self.decrypted_message = None

        print(self.own_pem_private_key)
        print(self.own_pem_public_key)
        print("=" * 50)

    def send_message(self, message, recipient_public_key_pem):
        """
        Encrypts a message using the recipient's public key.
        """
        if not recipient_public_key_pem:
            raise ValueError("Public key is not set. Please generate keys first.")

        self.message = message
        encrypted_message, encrypted_symmetric_key_to_send_to_recipient = (
            self._encrypt_message(recipient_public_key_pem, message)
        )

        return encrypted_message, encrypted_symmetric_key_to_send_to_recipient

    def receive_message(self, encrypted_message, encrypted_symmetric_key_from_sender):
        """
        Decrypts a message using the recipient's private key.
        """
        if not self.own_pem_private_key:
            raise ValueError("Private key is not set. Please generate keys first.")

        decrypted_message = self._decrypt_message(
            encrypted_message, encrypted_symmetric_key_from_sender
        )

        return decrypted_message

    def _generate_keys(self):
        """
        Generates a new RSA public/private key pair.
        """
        if not os.environ.get("OWN_PEM_PRIVATE_KEY") or not os.environ.get(
            "OWN_PEM_PUBLIC_KEY"
        ):
            print("Generating new RSA key pair...")

            missing_keys = (
                (
                    "OWN_PEM_PRIVATE_KEY"
                    if not os.environ.get("OWN_PEM_PRIVATE_KEY")
                    else ""
                ),
                (
                    "OWN_PEM_PUBLIC_KEY"
                    if not os.environ.get("OWN_PEM_PUBLIC_KEY")
                    else ""
                ),
            )

            print("Missing keys:", missing_keys)

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            public_key = private_key.public_key()

            # Serialize keys to PEM format for easy storage and transfer
            own_private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            
            own_public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Convert bytes to string with \n for .env compatibility
            own_private_pem_str = own_private_pem.decode("utf-8").replace("\n", "\\n")
            own_public_pem_str = own_public_pem.decode("utf-8").replace("\n", "\\n")

            print(
                "\nCopy and paste the following into your .env file:\n"
                f'OWN_PEM_PRIVATE_KEY={own_private_pem_str}\n'
                f'OWN_PEM_PUBLIC_KEY={own_public_pem_str}\n'
            )

            # Also return as bytes for internal use
            self.own_pem_private_key = own_private_pem
            self.own_pem_public_key = own_public_pem

            return self.own_pem_private_key, self.own_pem_public_key
        else:
            return self.own_pem_private_key, self.own_pem_public_key

    def _encrypt_message(self, recipient_public_key_pem, message: str):
        """
        Encrypts a message using a hybrid encryption scheme.
        """
        # Load the recipient's public key
        public_key = serialization.load_pem_public_key(recipient_public_key_pem)

        # 1. Generate a new symmetric key for this message
        symmetric_key = Fernet.generate_key()
        f = Fernet(symmetric_key)

        # 2. Encrypt the message with the symmetric key
        self.encrypted_message = f.encrypt(message.encode())

        # 3. Encrypt the symmetric key with the recipient's public RSA key
        # This is the key that will be sent along with the encypted message to the recipient
        self.encrypted_symmetric_key_to_send_to_recipient = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return self.encrypted_message, self.encrypted_symmetric_key_to_send_to_recipient

    def _decrypt_message(self, encrypted_message, encrypted_symmetric_key_from_sender):
        """
        Decrypts a message using a hybrid encryption scheme.
        """
        # Load your private key
        private_key = serialization.load_pem_private_key(
            self.own_pem_private_key, password=None
        )

        # 1. Decrypt the symmetric key with your private RSA key
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key_from_sender,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 2. Decrypt the message with the now-revealed symmetric key
        f = Fernet(symmetric_key)
        decrypted_message = f.decrypt(encrypted_message)
        self.decrypted_message = decrypted_message.decode()
        return self.decrypted_message


encrypt = HybirdEncryption()

private, public = encrypt._generate_keys()

# print("Private key:", private)
# print("Public key:", public)

message = "Example message to encrypt and send."

encrypted_message, encrypted_symmetric_key = encrypt.send_message(
    message, encrypt.own_pem_public_key
)

print("Encrypted message starts on new line:\n\n", encrypted_message, "\n")
print(
    "Encrypted symmetric key to send to recipient starts on new line:\n\n",
    encrypted_symmetric_key,
    "\n",
)

original_message = encrypt.receive_message(encrypted_message, encrypted_symmetric_key)

print("Original message:", message)

# # --- How to Use It ---

# # 1. The RECIPIENT generates a key pair.
# #    They must save the private key and keep it secret.
# #    They send the public key to the sender.
# private_key, public_key = generate_keys()

# # 2. The SENDER has a message to send.
# secret_message = "This is a secret message that will be sent via Gmail."

# # 3. The SENDER uses the RECIPIENT's public key to encrypt the message.
# encrypted_message, encrypted_key = encrypt_message(public_key, secret_message)

# # The sender would now send `encrypted_message` and `encrypted_key`
# # to the recipient (e.g., in the body of an email).

# # 4. The RECIPIENT receives the two encrypted components.
# #    They use their own PRIVATE key to decrypt.
# decrypted_message = decrypt_message(private_key, encrypted_message, encrypted_key)

# print("Original Message:", secret_message)
# print("\n---Sending via Gmail---")
# print("Encrypted Message Sent:", encrypted_message)
# print("Encrypted Key Sent:", encrypted_key)
# print("\n---Recipient Side---")
# print("Decrypted Message:", decrypted_message)

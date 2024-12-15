import sys, base64, struct, os, logging
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2
from pathlib import Path

logger = logging.getLogger()

class SecureDropUtils:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SecureDropUtils, cls).__new__(cls, *args, **kwargs)
        return cls._instance
        

    def __init__(self):
        """
        Initializes the secure drop utility class with default file paths and attributes.

        Attributes:
            _PUBLIC_KEY_PATH (str): Path to the public key file.
            _PRIVATE_KEY_PATH (str): Path to the private key file.
            CA_CERT_PATH (str): Path to the CA certificate file.
            CLIENT_CERT_PATH (str): Path to the client certificate file.
            USER_JSON_PATH (str): Path to the user JSON file.
            CONTACTS_JSON_PATH (str): Path to the contacts JSON file.
            LOG_FILE_PATH (str): Path to the log file.
            INBOX_PATH (str): Path to the inbox directory.
            _private_key (None): Placeholder for the private key.
            _public_key (None): Placeholder for the public key.
            _username (None): Placeholder for the username.
            _email (None): Placeholder for the email.

        Note:
            The directories for LOG_FILE_PATH and INBOX_PATH are created if they do not exist.
        """
        if not hasattr(self, "_PUBLIC_KEY_PATH"):
            self._PUBLIC_KEY_PATH = str(Path(__file__).parent / ".keys/client.pub")
        if not hasattr(self, "_PRIVATE_KEY_PATH"):
            self._PRIVATE_KEY_PATH = str(Path(__file__).parent / ".keys/client.key")
        if not hasattr(self, "CA_CERT_PATH"):
            self.CA_CERT_PATH = str(Path(__file__).parent / ".keys/ca.crt")
        if not hasattr(self, "CLIENT_CERT_PATH"):
            self.CLIENT_CERT_PATH = str(Path(__file__).parent / ".keys/client.crt")
        if not hasattr(self, "USER_JSON_PATH"):
            self.USER_JSON_PATH = str(Path(__file__).parent / ".db/user.json")
        if not hasattr(self, "CONTACTS_JSON_PATH"):
            self.CONTACTS_JSON_PATH = str(Path(__file__).parent / ".db/contacts.json")
        if not hasattr(self, "LOG_FILE_PATH"):
            self.LOG_FILE_PATH = str(Path(__file__).parent / ".db/secure_drop.log")
            log_dir = Path(self.LOG_FILE_PATH).parent
            log_dir.mkdir(parents=True, exist_ok=True)
        if not hasattr(self, "LOCK_FILE"):
            self.LOCK_FILE = str(Path(__file__).parent / ".db/lock")
        if not hasattr(self, "INBOX_PATH"):
            self.INBOX_PATH = str(Path(__file__).parent / "inbox/")
            inbox_dir = Path(self.INBOX_PATH)
            inbox_dir.mkdir(parents=True, exist_ok=True)
        if not hasattr(self, "_private_key"):
            self._private_key = None
        if not hasattr(self, "_public_key"):
            self._public_key = None
        if not hasattr(self, "_username"):
            self._username = None
        if not hasattr(self, "_email"):
            self._email = None


    def pgp_encrypt_and_sign_data(self, data: str, recipient_public_key: RSA.RsaKey) -> bytes:
        """
        Encrypts and signs the given data using PGP (Pretty Good Privacy) encryption.
        This method performs the following steps:
        1. Generates a random session key for AES encryption.
        2. Encrypts the session key using the recipient's RSA public key.
        3. Encrypts the data using AES encryption with the generated session key.
        4. Creates a SHA-512 hash of the data and signs it with the sender's private RSA key.
        5. Packages the encrypted session key, AES nonce, ciphertext, and signature into a single byte sequence.
        Args:
            data (str): The plaintext data to be encrypted and signed.
            recipient_public_key (RSA.RsaKey): The recipient's RSA public key used to encrypt the session key.
        Returns:
            bytes: A byte sequence containing the encrypted session key, AES nonce, ciphertext, and signature.
        Raises:
            RuntimeError: If an error occurs during the encryption or signing process.
        """
        try:
            
            session_key = get_random_bytes(32)
            cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
            session_key_encrypted = cipher_rsa.encrypt(session_key)
            
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode("utf-8"))
            
            hashed_data = SHA512.new(truncate="256")
            hashed_data.update(data.encode("utf-8"))
            signature = pkcs1_15.new(self._private_key).sign(hashed_data)
            
            result = (
                b"ENCRYPTED\n" +
                struct.pack("I", len(session_key_encrypted)) + session_key_encrypted +
                struct.pack("I", len(cipher_aes.nonce)) + cipher_aes.nonce +
                struct.pack("I", len(tag)) + tag +
                struct.pack("I", len(ciphertext)) + ciphertext +
                struct.pack("I", len(signature)) + signature
            )
            return result
        except Exception as e:
            print("An error occurred while encrypting the data.")
            print(f"Exception: {e}")
            raise RuntimeError("An error occurred while encrypting the data.")
        

    def pgp_decrypt_and_verify_data(self, data: bytes, sender_public_key: RSA.RsaKey) -> bytes:
        """
        Decrypts and verifies PGP encrypted data.
        This method decrypts data that was encrypted using PGP encryption and verifies its signature.
        The data is expected to be in a specific format, starting with "ENCRYPTED\n" followed by the
        encrypted session key, nonce, tag, ciphertext, and signature.
        Args:
            data (bytes): The encrypted data to be decrypted and verified.
            sender_public_key (RSA.RsaKey): The sender's RSA public key used for signature verification.
        Returns:
            bytes: The decrypted data if decryption and verification are successful, otherwise None.
        Raises:
            ValueError: If the data format is invalid or signature verification fails.
        """
        try:
            if not data.startswith(b"ENCRYPTED\n"):
                raise ValueError("Invalid format.")
            
            data = data[len(b"ENCRYPTED\n"):]
            offset = 0

            session_key_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            encrypted_session_key = data[offset:offset + session_key_len]
            offset += session_key_len

            nonce_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            nonce = data[offset:offset + nonce_len]
            offset += nonce_len

            tag_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            tag = data[offset:offset + tag_len]
            offset += tag_len
            
            ciphertext_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            ciphertext = data[offset:offset + ciphertext_len]
            offset += ciphertext_len

            signature_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            signature = data[offset:offset + signature_len]
        
            cipher_rsa = PKCS1_OAEP.new(self._private_key)
            session_key = cipher_rsa.decrypt(encrypted_session_key)
            
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag).decode("utf-8")
            
            hasher = SHA512.new(truncate="256")
            hasher.update(data.encode("utf-8"))
            
            try:
                pkcs1_15.new(sender_public_key).verify(hasher, signature)
                return data
            except ValueError:
                raise ValueError("Signature verification failed.")
        except Exception as e:
            print("An error occurred while decrypting the data.")
            print(f"Exception: {e}")
            return None
        

    def encrypt_and_sign(self, data: bytes) -> bytes:
        """
        Encrypts and signs the given data using RSA and AES encryption.
        This method performs the following steps:
        1. Generates a random session key for AES encryption.
        2. Encrypts the session key using the provided RSA public key.
        3. Encrypts the data using AES encryption with the generated session key.
        4. Computes a SHA-512 hash of the data and signs it using the provided RSA private key.
        5. Combines the encrypted session key, AES nonce, AES tag, ciphertext, and signature into a single byte sequence.
        Args:
            data (bytes): The data to be encrypted and signed.
        Returns:
            bytes: A byte sequence containing the encrypted session key, AES nonce, AES tag, ciphertext, and signature.
            None: If an error occurs during the encryption or signing process.
        Raises:
            ValueError: If the public or private key is not found.
        """
        try:
            if self._public_key is None or self._private_key is None:
                raise ValueError("Public or private key not found.")
            
            session_key = get_random_bytes(32)
            cipher_rsa = PKCS1_OAEP.new(self._public_key)
            session_key_encrypted = cipher_rsa.encrypt(session_key)
            
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data)
            
            hashed_data = SHA512.new(truncate="256")
            hashed_data.update(data)
            signature = pkcs1_15.new(self._private_key).sign(hashed_data)
            
            
            result = (
                b"ENCRYPTED\n" +
                struct.pack("I", len(session_key_encrypted)) + session_key_encrypted +
                struct.pack("I", len(cipher_aes.nonce)) + cipher_aes.nonce +
                struct.pack("I", len(tag)) + tag +
                struct.pack("I", len(ciphertext)) + ciphertext +
                struct.pack("I", len(signature)) + signature
            )
            return result
        except Exception as e:
            print("An error occurred while encrypting the data.")
            print("Exception:", e)
            return None
            

    def decrypt_and_verify(self, data: bytes) -> bytes:
        """
        Decrypts and verifies the given encrypted data.
        The data is expected to be in a specific format:
        - Starts with the string "ENCRYPTED\n"
        - Followed by the length and content of the encrypted session key
        - Followed by the length and content of the nonce
        - Followed by the length and content of the tag
        - Followed by the length and content of the ciphertext
        - Followed by the length and content of the signature
        The method performs the following steps:
        1. Checks if the data starts with "ENCRYPTED\n".
        2. Extracts the encrypted session key, nonce, tag, ciphertext, and signature from the data.
        3. Decrypts the session key using the RSA private key.
        4. Decrypts the ciphertext using the decrypted session key and nonce.
        5. Verifies the integrity of the decrypted data using the tag.
        6. Verifies the signature of the decrypted data using the RSA public key.
        Args:
            data (bytes): The encrypted data to be decrypted and verified.
        Returns:
            bytes: The decrypted data if decryption and verification are successful.
            None: If an error occurs during decryption or verification.
        Raises:
            ValueError: If the file format is invalid, the password is incorrect, or signature verification fails.
        """
        try:
            if not data.startswith(b"ENCRYPTED\n"):
                print("Invalid file format or incorrect password.")
                raise ValueError("Invalid file format or incorrect password.")
            
            data = data[len(b"ENCRYPTED\n"):]
            offset = 0
    
            session_key_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            encrypted_session_key = data[offset:offset + session_key_len]
            offset += session_key_len

            nonce_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            nonce = data[offset:offset + nonce_len]
            offset += nonce_len

            tag_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            tag = data[offset:offset + tag_len]
            offset += tag_len
            
            ciphertext_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            ciphertext = data[offset:offset + ciphertext_len]
            offset += ciphertext_len

            signature_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            signature = data[offset:offset + signature_len]


            cipher_rsa = PKCS1_OAEP.new(self._private_key)
            session_key = cipher_rsa.decrypt(encrypted_session_key)
            
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
            
            hasher = SHA512.new(truncate="256")
            hasher.update(decrypted_data)
            
            try:
                pkcs1_15.new(self._public_key).verify(hasher, signature)
                return decrypted_data
            except:
                print("Signature verification failed.")
                raise ValueError("Signature verification failed.")
        except Exception as e:
            print("An error occurred while decrypting the data.")
            print("Exception:", e)
            return None


    def hash_data(self, data: str) -> str:
        """
        Hashes the provided data using SHA-512 with a random salt and returns the salted hash in base64 encoding.
        Args:
            data (str): The data to be hashed.
        Returns:
            str: The salted hash of the data in the format "$salt$hashed_password", both in base64 encoding.
            None: If an error occurs during hashing.
        Raises:
            Exception: If an error occurs during hashing, it will be caught and printed.
        """
        try:
            salt = get_random_bytes(16)
            hasher = SHA512.new(truncate="256")
            hasher.update(salt + data.encode("utf-8"))
            hashed_password = hasher.digest()
            
            salt_b64 = base64.b64encode(salt).decode("utf-8")
            hashed_password_b64 = base64.b64encode(hashed_password).decode("utf-8")
            
            salted_hash = f"${salt_b64}${hashed_password_b64}"
            return salted_hash
        except:
            print("An error occurred while hashing the data.")
            print("Exception:", sys.exc_info()[0])
            return None


    def verify_hash(self, data: str, hashed_data: str) -> bool:
        """
        Verifies if the provided data matches the hashed data.
        Args:
            data (str): The plain text data to verify.
            hashed_data (str): The hashed data in the format "salt$hashed_password".
        Returns:
            bool: True if the data matches the hashed data, False otherwise.
        Raises:
            Exception: If an error occurs during the verification process.
        """
        try:
            salt_b64, hashed_password_b64 = hashed_data.split("$")[1:]
            salt = base64.b64decode(salt_b64)
            hashed_password = base64.b64decode(hashed_password_b64)
            
            hasher = SHA512.new(truncate="256")
            hasher.update(salt + data.encode("utf-8"))
            return hashed_password == hasher.digest()
        except:
            print("An error occurred while verifying the hash.")
            print("Exception:", sys.exc_info()[0])
            return False


    def verify_key_pair(self) -> None:
        """
        Verifies the existence and validity of the RSA key pair.
        This method checks if the public and private key files exist at the specified paths.
        If the files exist, it attempts to read and import the keys to ensure they are in the correct format.
        If any error occurs during this process, an appropriate exception is raised and the program exits.
        Raises:
            FileNotFoundError: If either the public or private key file does not exist.
            ValueError: If the private or public key is not in the correct format.
            Exception: For any other exceptions that occur during the verification process.
        """
        try:
            if not os.path.exists(self._PUBLIC_KEY_PATH) or not os.path.exists(self._PRIVATE_KEY_PATH):
                raise FileNotFoundError("Key pair not found.")
            
            with open(self._PRIVATE_KEY_PATH, "rb") as file:
                private_key = file.read()
                if private_key.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
                    try:
                        self._private_key = RSA.import_key(private_key)
                    except Exception as e:
                        raise ValueError(f"Invalid private key format: {e}")
                    
            with open(self._PUBLIC_KEY_PATH, "rb") as file:
                public_key = file.read()
                if public_key.startswith(b"-----BEGIN PUBLIC KEY-----"):
                    try:
                        self._public_key = RSA.import_key(public_key)
                    except Exception as e:
                        raise ValueError(f"Invalid public key format: {e}")
                    
        except Exception as e:
            print("An error occurred while verifying the key pair.")
            print("Exception:", e)
            sys.exit()
                

    def encrypt_private_key(self, password: str) -> None:
        """
        Encrypts the private key stored at the specified path using the provided password.
        This method reads the private key from the file, encrypts it using AES encryption
        with a key derived from the provided password and a randomly generated salt, and
        then writes the encrypted key back to the file.
        Args:
            password (str): The password to use for deriving the encryption key.
        Raises:
            Exception: If an error occurs during the encryption process, an exception is caught
                       and an error message is printed.
        """
        try:
            with open(self._PRIVATE_KEY_PATH, "rb") as file:
                private_key = RSA.import_key(file.read())
            
            salt = get_random_bytes(16)
            key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)
            
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(private_key.export_key())
            
            with open(self._PRIVATE_KEY_PATH, "wb") as file:
                result = (
                    b"ENCRYPTED\n" +
                    struct.pack("I", len(salt)) + salt +
                    struct.pack("I", len(cipher.nonce)) + cipher.nonce +
                    struct.pack("I", len(tag)) + tag +
                    struct.pack("I", len(ciphertext)) + ciphertext
                )
                file.write(result)
            
        except:
            print("An error occurred while encrypting the private key with password.")
            print("Exception:", sys.exc_info()[0])
    
    
    def decrypt_private_key(self, password: str) -> bool:
        """
        Decrypts the private key using the provided password.
        This method attempts to decrypt the private key stored at the path specified by 
        `self._PRIVATE_KEY_PATH`. If the private key is already in an unencrypted format, 
        it will re-encrypt it using the provided password. If the private key is in an 
        encrypted format, it will decrypt it using the provided password and load it into 
        `self._private_key`. The corresponding public key is loaded from the path specified 
        by `self._PUBLIC_KEY_PATH`.
        Args:
            password (str): The password used to decrypt the private key.
        Returns:
            bool: True if the private key was successfully decrypted or re-encrypted, 
                  False otherwise.
        """
        try:
            with open(self._PRIVATE_KEY_PATH, "rb") as file:
                data = file.read()
                if data.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
                    self.encrypt_private_key(password)
                    return True
            with open(self._PRIVATE_KEY_PATH, "rb") as file:
                data = file.read()
            if not data.startswith(b"ENCRYPTED\n"):
                return False
        
            data = data[len(b"ENCRYPTED\n"):]
            offset = 0
    
            salt_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            salt = data[offset:offset + salt_len]
            offset += salt_len

            nonce_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            nonce = data[offset:offset + nonce_len]
            offset += nonce_len

            tag_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            tag = data[offset:offset + tag_len]
            offset += tag_len
            
            ciphertext_len = struct.unpack("I", data[offset:offset + 4])[0]
            offset += 4
            ciphertext = data[offset:offset + ciphertext_len]
            offset += ciphertext_len


            key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)

            cipher = AES.new(key, AES.MODE_EAX, nonce)
            private_key = cipher.decrypt_and_verify(ciphertext, tag)
            
            if private_key.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):      
                self._private_key = RSA.import_key(private_key)
                with open(self._PUBLIC_KEY_PATH, "r") as file:
                    self._public_key = RSA.import_key(file.read())
                    
                return True
            else:
                return False
        except Exception as e:
            return False

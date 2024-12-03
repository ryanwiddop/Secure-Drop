import os, sys, base64, struct, socket, ssl
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

CA_HOST = "10.10.55.10"

class SecureDropUtils:
    """
    SecureDropUtils is a singleton class that provides various cryptographic utilities for secure data transmission and storage.
    Attributes:
        __instance (SecureDropUtils): The singleton instance of the class.
        _private_key (RSA.RsaKey): The private RSA key used for encryption and signing.
        _public_key (RSA.RsaKey): The public RSA key used for encryption and verification.
        _username (str): The username associated with the keys.
        _email (str): The email associated with the keys.
        __initialized (bool): A flag indicating whether the instance has been initialized.
    Methods:
        pgp_encrypt_and_sign_data(data: str) -> dict:
            Encrypts and signs the given data using PGP encryption.
        pgp_decrypt_and_verify_data(data: dict) -> str:
            Decrypts and verifies the given encrypted data using PGP decryption.
        encrypt_and_sign(data: bytes) -> bytes:
            Encrypts and signs the given data using RSA and AES encryption.
        decrypt_and_verify(data: bytes) -> bytes:
            Decrypts and verifies the given encrypted data using RSA and AES decryption.
        hash_data(data: str) -> str:
            Hashes the given data using SHA-512 with a random salt and returns the salted hash.
        verify_hash(data: str, hashed_data: str) -> bool:
        verify_key_pair() -> None:
            Verifies the existence of the key pair and generates a new one if not present.
        encrypt_private_key(password: str) -> None:
            Encrypts the private key with the given password and stores it securely.
        decrypt_private_key(password: str) -> bool:
            Decrypts the private key with the given password and loads it into the instance.
    """
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SecureDropUtils, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    
    def __init__(self):
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
        if not hasattr(self, "_private_key"):
            self._private_key = None
        if not hasattr(self, "_public_key"):
            self._public_key = None

    def pgp_encrypt_and_sign_data(self, data: str, recipient_public_key: RSA.RsaKey) -> bytes:
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
                b'ENCRYPTED\n' +
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
        try:
            if not data.startswith(b'ENCRYPTED\n'):
                raise ValueError("Invalid format.")
            
            data = data[len(b'ENCRYPTED\n'):]
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
        Encrypts and signs the given data using RSA and AES encryption algorithms.
        This method performs the following steps:
        1. Generates a random session key for AES encryption.
        2. Encrypts the session key using the user's RSA public key.
        3. Encrypts the data using the AES session key in EAX mode.
        4. Computes a SHA-512 hash of the data and signs it using the user's RSA private key.
        5. Packages the encrypted session key, AES nonce, authentication tag, ciphertext, and signature into a single byte string.
        Args:
            data (bytes): The data to be encrypted and signed.
        Returns:
            bytes: A byte string containing the encrypted session key, AES nonce, authentication tag, ciphertext, and signature.
            None: If an error occurs during the encryption or signing process.
        Raises:
            Exception: If an error occurs during the encryption or signing process.
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
                b'ENCRYPTED\n' +
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
        Decrypts and verifies the provided encrypted data.
        Args:
            data (bytes): The encrypted data to be decrypted and verified.
        Returns:
            bytes: The decrypted data if decryption and verification are successful.
            None: If an error occurs during decryption or verification.
        Raises:
            ValueError: If the file format is invalid, the password is incorrect, or signature verification fails.
        """
        try:
            if not data.startswith(b'ENCRYPTED\n'):
                print("Invalid file format or incorrect password.")
                raise ValueError("Invalid file format or incorrect password.")
            
            data = data[len(b'ENCRYPTED\n'):]
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
            str: The salted hash of the data in the format "$salt$hashed_password" where both salt and hashed_password are base64 encoded.
            None: If an error occurs during hashing.
        Raises:
            Exception: If an error occurs during hashing, the exception is caught and None is returned.
        """
        try:
            salt = get_random_bytes(16)
            hasher = SHA512.new(truncate="256")
            hasher.update(salt + data.encode("utf-8"))
            hashed_password = hasher.digest()
            
            salt_b64 = base64.b64encode(salt).decode('utf-8')
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
            data (str): The original data to verify.
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

    # DEPRECATED
    # def verify_key_pair(self) -> None:
    #     try:
    #         if not os.path.exists(self._PUBLIC_KEY_PATH) or not os.path.exists(self._PRIVATE_KEY_PATH):
    #             os.makedirs(str(Path(__file__).parent / ".keys/"), exist_ok=True)  
                              
    #             private_key = RSA.generate(2048)
    #             public_key = private_key.publickey()
    #             self._private_key = private_key
    #             self._public_key = public_key
                
    #             with open(self._PRIVATE_KEY_PATH, "wb") as private_file:
    #                 private_file.write(private_key.export_key())
    #                 os.chmod(self._PRIVATE_KEY_PATH, 0o660)
    #             with open(self._PUBLIC_KEY_PATH, "wb") as public_file:
    #                 public_file.write(public_key.export_key())
    #                 os.chmod(self._PUBLIC_KEY_PATH, 0o660)
        
    #     except Exception as e:
    #         print("An error occurred while verifying the key pair.")
    #         print("Exception:", e)
    #         sys.exit()
                
    def encrypt_private_key(self, password: str) -> None:
        """
        Encrypts the private key stored at the specified path using the provided password.
        This function reads the private key from the file, encrypts it using AES encryption
        with a key derived from the provided password and a random salt using PBKDF2, and
        then writes the encrypted private key back to the file.
        Args:
            password (str): The password to use for encrypting the private key.
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
                    b'ENCRYPTED\n' +
                    struct.pack("I", len(salt)) + salt +
                    struct.pack("I", len(cipher.nonce)) + cipher.nonce +
                    struct.pack("I", len(tag)) + tag +
                    struct.pack("I", len(ciphertext)) + ciphertext
                )
                file.write(result)
            
        except:
            print("An error occurred while encrypting the private key with password.")
            print("Exception:", sys.exc_info()[0])
         
    # DEPRECATED
    # def encrypt_private_key_on_exit(self) -> None:
    #     try:
    #         with open(_PRIVATE_KEY_PATH, "rb") as file:
    #             private_key = RSA.import_key(file.read())
            
    #         cipher = AES.new(exit_key, AES.MODE_EAX)
    #         ciphertext, tag = cipher.encrypt_and_digest(private_key.export_key())

    #         with open(_PRIVATE_KEY_PATH, "wb") as file:
    #             result = (
    #                 b'ENCRYPTED\n' +
    #                 struct.pack("I", len(exit_key_salt)) + exit_key_salt +
    #                 struct.pack("I", len(cipher.nonce)) + cipher.nonce +
    #                 struct.pack("I", len(tag)) + tag +
    #                 struct.pack("I", len(ciphertext)) + ciphertext
    #             )
    #             file.write(result)
            
    #     except:
    #         print("An error occurred while encrypting the private key with exit key.")
    #         print("Exception:", sys.exc_info()[0])
    
    # DEPRECATED
    # def decrypt_private_key(self, password: str) -> bool:
    #     """
    #     Decrypts the private key using the provided password.
    #     This method attempts to decrypt the private key stored at the path specified by `_PRIVATE_KEY_PATH`.
    #     If the private key is already in plaintext format, it will be re-encrypted using the provided password.
    #     Otherwise, it will decrypt the private key using the provided password and the stored salt, nonce, and tag.
    #     Args:
    #         password (str): The password used to decrypt the private key.
    #     Returns:
    #         bool: True if the decryption is successful, False otherwise.
    #     """
    #     try:
    #         with open(self._PRIVATE_KEY_PATH, "rb") as file:
    #             data = file.read()
    #             if data.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
    #                 self.__encrypt_private_key(password)
    #                 return True
    #         with open(self._PRIVATE_KEY_PATH, "rb") as file:
    #             data = file.read()
            
    #         if not data.startswith(b'ENCRYPTED\n'):
    #             return False
            
    #         data = data[len(b'ENCRYPTED\n'):]
    #         offset = 0
    
    #         salt_len = struct.unpack("I", data[offset:offset + 4])[0]
    #         offset += 4
    #         salt = data[offset:offset + salt_len]
    #         offset += salt_len

    #         nonce_len = struct.unpack("I", data[offset:offset + 4])[0]
    #         offset += 4
    #         nonce = data[offset:offset + nonce_len]
    #         offset += nonce_len

    #         tag_len = struct.unpack("I", data[offset:offset + 4])[0]
    #         offset += 4
    #         tag = data[offset:offset + tag_len]
    #         offset += tag_len
            
    #         ciphertext_len = struct.unpack("I", data[offset:offset + 4])[0]
    #         offset += 4
    #         ciphertext = data[offset:offset + ciphertext_len]
    #         offset += ciphertext_len


    #         key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)

    #         cipher = AES.new(key, AES.MODE_EAX, nonce)
    #         private_key = cipher.decrypt_and_verify(ciphertext, tag)
            
    #         self._private_key = RSA.import_key(private_key)
    #         with open(self._PUBLIC_KEY_PATH, "r") as file:
    #             self._public_key = RSA.import_key(file.read())
            
    #         return True
    #     except Exception as e:
    #         return False
from secure_drop_utils import SecureDropUtils
import os, json, sys, socket, logging, ssl, time, tempfile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Hash import HMAC

logger = logging.getLogger()

def _verify_contact_file() -> None:
    """
    Verifies the existence and integrity of the contacts JSON file.
    This function checks if the contacts JSON file exists. If it does not exist,
    it creates a new file with an empty contacts list, encrypts, and signs it.
    If the file exists, it reads the file and checks if the data is properly
    encrypted and signed. If the data is invalid or decryption and verification
    fail, it overwrites the file with a new encrypted and signed empty contacts list.
    Raises:
        ValueError: If decryption and verification of the existing file data fail.
        SystemExit: If any other exception occurs during the process.
    """
    sdutils = SecureDropUtils()
    try:
        if not os.path.exists(sdutils.CONTACTS_JSON_PATH):
            with open(sdutils.CONTACTS_JSON_PATH, "wb") as file:
                file.write(sdutils.encrypt_and_sign(json.dumps({"contacts": []}).encode("utf-8")))
                
        else:
            with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
                data = file.read()
                if not data.startswith(b'ENCRYPTED\n') or len(data) <= 9:
                    with open(sdutils.CONTACTS_JSON_PATH, "wb") as file:
                        file.write(sdutils.encrypt_and_sign(json.dumps({"contacts": []}).encode("utf-8")))
                else:
                    data = sdutils.decrypt_and_verify(data)
                    if data is None:
                        raise ValueError("Decryption and verification failed.")
                    data = json.loads(data.decode("utf-8"))
                    if "contacts" not in data:
                        with open(sdutils.CONTACTS_JSON_PATH, "wb") as file:
                            file.write(sdutils.encrypt_and_sign(json.dumps({"contacts": []}).encode("utf-8")))
    except Exception as e:
        print("An error occurred while verifying the contacts file.")
        print("Exception:", e)
        sys.exit()

def sync_contacts():
    """
    Synchronizes the contacts with the server.

    This function discovers servers, verifies their certificates, and synchronizes the contacts list.
    It updates the online status of contacts based on the server responses.

    Parameters:
        contacts (list): The list of contacts to be synchronized.

    Raises:
        ValueError: If decryption and verification of the contacts file fails.
        Exception: For any other errors that occur during the process.
    """
    sdutils = SecureDropUtils()
    SERVER_PORT = 23325
    DISCOVERY_PORT = 23326
    servers = []

    client_discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client_discovery_socket.settimeout(2)
    client_discovery_socket.sendto(b"DISCOVER_SECURE_DROP", ("<broadcast>", DISCOVERY_PORT))
    
    start_time = time.time()
    
    own_ip = socket.gethostbyname(socket.gethostname())
    
    while True:
        try:
            response, addr = client_discovery_socket.recvfrom(1024)
            if addr[0] == own_ip:
                continue
            
            server_cert = x509.load_pem_x509_certificate(response, default_backend())
            with open(sdutils.CA_CERT_PATH, "rb") as file:
                ca_cert = x509.load_pem_x509_certificate(file.read(), default_backend())
            
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                server_cert.signature_hash_algorithm
            )
            servers.append(addr)
            
        except socket.timeout:
            pass
        except Exception as e:
            logger.info(f"Certificate verification failed for {addr}: {e}")
        if time.time() - start_time > 2:
            break
    client_discovery_socket.close() 
            

    for server in servers:
        try:
            print()
            client_socket = socket.socket()
            client_socket.connect((server[0], SERVER_PORT))
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(sdutils.CA_CERT_PATH)
            with tempfile.NamedTemporaryFile() as private_key_file:
                private_key_file.write(sdutils._private_key.export_key())
                private_key_file.flush()
                private_key_file.seek(0)
                context.load_cert_chain(certfile=sdutils.CLIENT_CERT_PATH, keyfile=private_key_file.name)
            client_socket = context.wrap_socket(client_socket, server_hostname="SecureDrop")
                    
            cryptography_server_cert = client_socket.getpeercert()
            cryptography_server_cert = x509.load_pem_x509_certificate(cryptography_server_cert, default_backend())
            cryptography_server_public_key = cryptography_server_cert.public_key()
            sender_public_key_bytes = cryptography_server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sender_public_key = RSA.import_key(sender_public_key_bytes)
            
            encrypted_shared_secret_key = client_socket.recv(1024)
            shared_key = sdutils.pgp_decrypt_and_verify_data(encrypted_shared_secret_key, sender_public_key)
            if shared_key is None:
                logger.warning(f"Failed to decrypt and verify shared key from {server}")
                continue
            
            encrypted_challenge = client_socket.recv(1024)
            challenge = sdutils.decrypt_and_verify(encrypted_challenge, sender_public_key)
            if challenge is None:
                logger.warning(f"Failed to decrypt and verify challenge from {server}")
                continue
            
            challenge_hash = HMAC.new(shared_key, challenge, digestmod=SHA512).digest()
            encrypted_challenge_hash = sdutils.pgp_encrypt_and_sign_data(challenge_hash, sender_public_key)
            client_socket.send(encrypted_challenge_hash)
            
            command = sdutils.pgp_encrypt_and_sign_data(b"SYNC_CONTACTS", sender_public_key)
            client_socket.send(command)
            
            encrypted_server_name = client_socket.recv(1024)
            encrypted_server_email = client_socket.recv(1024)
            server_name = sdutils.pgp_decrypt_and_verify_data(encrypted_server_name, sender_public_key)
            server_email = sdutils.pgp_decrypt_and_verify_data(encrypted_server_email, sender_public_key)
            
            with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
                data = sdutils.decrypt_and_verify(file.read())
                if data is None:
                    raise ValueError("Decryption and verification failed.")
                data = json.loads(data.decode("utf-8"))
                contacts = data["contacts"]
                for contact in contacts:
                    if contact["name"] == server_name and contact["email"] == server_email:
                        contact["online"] = True
            
            with open(sdutils.CONTACTS_JSON_PATH, "wb") as file:
                file.write(sdutils.encrypt_and_sign(json.dumps({"contacts": contacts}).encode("utf-8")))
                
            client_socket.close()
        except Exception as e:
            logger.warning(f"Failed to sync contacts with {server}: {e}")
            client_socket.close()
            continue
    
def add_contact() -> None:
    """
    Adds a new contact to the contacts list.
    Prompts the user to enter a full name and email address for the new contact.
    The contact is then added to the existing contacts list stored in a JSON file.
    The file is encrypted and signed for security.
    Raises:
        ValueError: If decryption and verification of the contacts file fails.
        Exception: For any other errors that occur during the process.
    """
    try:
        sdutils = SecureDropUtils()
        
        _verify_contact_file()
        name = input("  Enter Full Name: ")
        email = input("  Enter Email Address: ")
        new_contact = {
            "name": name,
            "email": email,
            "online": False,
        }
        
        with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
            data = sdutils.decrypt_and_verify(file.read())
            if data is None:
                raise ValueError("Decryption and verification failed.")
            data = json.loads(data.decode("utf-8"))
            contacts = data["contacts"]
        
        contacts.append(new_contact)
        
        with open(sdutils.CONTACTS_JSON_PATH, "wb") as file:
            file.write(sdutils.encrypt_and_sign(json.dumps({"contacts": contacts}).encode("utf-8")))

        print("  Contact Added.\n")
        logger.info(f"Added contact.")
    except Exception as e:
        print("An error occurred while adding the contact.")
        print("Exception:", e)
        logger.error(f"Error adding contact: {e}")
        sys.exit()

def list_contacts() -> None:
    """
    Lists all contacts from the encrypted contacts file.

    This function performs the following steps:
    1. Verifies the existence and integrity of the contacts file.
    2. Opens and reads the encrypted contacts file.
    3. Decrypts and verifies the contents of the file.
    4. Parses the decrypted data as JSON.
    5. Synchronizes the contacts.
    6. Prints the list of contacts, indicating their online status.

    If any error occurs during these steps, an error message is printed and the program exits.

    Raises:
        ValueError: If decryption and verification of the file contents fail.
        Exception: For any other exceptions that occur during the process.
    """
    try:
        sdutils = SecureDropUtils()
        _verify_contact_file()
        sync_contacts()
        with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
            data = sdutils.decrypt_and_verify(file.read())
            if data is None:
                raise ValueError("Decryption and verification failed.")
            data = json.loads(data.decode("utf-8"))
            contacts = data["contacts"]
        print("  The following contacts are online:")
        for contact in contacts:
            if contact["online"]:
                print(f"  * {contact['name']} <{contact['email']}>")
    except Exception as e:
        print("An error occurred while listing the contacts.")
        print("Exception:", e)
        sys.exit()

from secure_drop_utils import SecureDropUtils
import os, json, sys, socket, logging, ssl, time, tempfile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Hash import HMAC

logger = logging.getLogger()

def _verify_contact_file() -> None:
    """
    Verifies the existence and integrity of the contacts JSON file.
    This function checks if the contacts JSON file exists at the path specified by
    `sdutils.CONTACTS_JSON_PATH`. If the file does not exist, it creates a new file
    with an empty contacts list, encrypts, and signs it. If the file exists, it reads
    the file and verifies its integrity. If the file is not properly encrypted or
    signed, or if it does not contain a valid contacts list, it overwrites the file
    with a new encrypted and signed empty contacts list.
    Raises:
        ValueError: If decryption and verification of the existing file fail.
        Exception: For any other errors that occur during the file verification process.
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

def _discover_servers() -> list:
    """
    Discovers SecureDrop servers on the local network.
    This function broadcasts a discovery message to the local network and listens for responses from SecureDrop servers.
    It verifies the server's certificate using a CA certificate and collects the addresses of the discovered servers.
    Returns:
        list: A list of tuples containing the addresses of the discovered servers.
    """
    sdutils = SecureDropUtils()
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
            response, addr = client_discovery_socket.recvfrom(4096)
            if addr[0] == own_ip:
                continue
            
            logger.info("Discovered server at: " + addr[0])
            
            server_cert = x509.load_pem_x509_certificate(response, default_backend())
            with open(sdutils.CA_CERT_PATH, "rb") as file:
                ca_cert = x509.load_pem_x509_certificate(file.read(), default_backend())
            
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                server_cert.signature_hash_algorithm
            )
            servers.append(addr)
            
        except socket.timeout:
            pass
        except Exception as e:
            logger.info(f"Exception caught while syncing contacts: {addr}: {e}")
        if time.time() - start_time > 2:
            break
    client_discovery_socket.close() 
    return servers

def sync_contacts():
    """
    Synchronizes the contacts by performing the following steps:
    1. Reads and decrypts the contacts data from a JSON file.
    2. Sets all contacts' online status to False.
    3. Encrypts and writes the updated contacts data back to the JSON file.
    4. Discovers available servers.
    5. For each discovered server:
        a. Establishes a secure SSL connection.
        b. Authenticates the server using its public key.
        c. Exchanges and verifies a shared secret key.
        d. Sends a synchronization command to the server.
        e. Sends the client's username and email to the server.
        f. Receives and decrypts the server's name and email.
        g. Updates the contact's online status if the server's name and email match a contact.
    6. Handles exceptions and logs appropriate warnings or errors.
    Raises:
        Exception: If any error occurs during the synchronization process.
    """
    sdutils = SecureDropUtils()
    with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
        data = sdutils.decrypt_and_verify(file.read())
        if data is None:
            logger.warning("Failed to decrypt and verify contacts data")
        
        if isinstance(data, dict):
            data = json.dumps(data).encode('utf-8')
        
        data = json.loads(data.decode("utf-8"))
        contacts = data["contacts"]
    for contact in contacts:
        contact["online"] = False
    
    with open(sdutils.CONTACTS_JSON_PATH, "wb") as file:
        file.write(sdutils.encrypt_and_sign(json.dumps({"contacts": contacts}).encode("utf-8")))

    servers = _discover_servers()        
    if not servers:
        logger.warning("No servers found")
        return
    elif servers is None:
        logger.warning("Failed to discover servers")
        return
    elif len(servers) == 0:
        logger.warning("No servers found")
        return

    for server in servers:
        SERVER_PORT = 23325
        try:
            client_socket = socket.socket()
            client_socket.connect((server[0], SERVER_PORT))
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.verify_mode = ssl.CERT_REQUIRED
            with tempfile.NamedTemporaryFile() as private_key_file:
                private_key_file.write(sdutils._private_key.export_key())
                private_key_file.flush()
                private_key_file.seek(0)
                context.load_cert_chain(certfile=sdutils.CLIENT_CERT_PATH, keyfile=private_key_file.name)
            context.load_verify_locations(sdutils.CA_CERT_PATH)
            client_socket = context.wrap_socket(client_socket, server_hostname="SecureDrop")
                    
            cryptography_server_cert_der = client_socket.getpeercert(binary_form=True)
            cryptography_server_cert = x509.load_der_x509_certificate(cryptography_server_cert_der, default_backend())
            cryptography_server_public_key = cryptography_server_cert.public_key()
            if cryptography_server_public_key is None:
                logger.warning(f"Failed to get public key from {server}")
                continue
            sender_public_key_bytes = cryptography_server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sender_public_key = RSA.import_key(sender_public_key_bytes)
            
            encrypted_shared_secret_key = client_socket.recv(1024)
            if encrypted_shared_secret_key is None:
                logger.warning(f"Failed to receive shared key from {server}")
                continue
            shared_key = sdutils.pgp_decrypt_and_verify_data(encrypted_shared_secret_key, sender_public_key)
            if shared_key is None:
                logger.warning(f"Failed to decrypt and verify shared key from {server}")
                continue
            
            encrypted_challenge = client_socket.recv(1024)
            if encrypted_challenge is None:
                logger.warning(f"Failed to receive challenge from {server}")
                continue
            challenge = sdutils.pgp_decrypt_and_verify_data(encrypted_challenge, sender_public_key)
            if challenge is None:
                logger.warning(f"Failed to decrypt and verify challenge from {server}")
                continue
            
            shared_key_bytes = bytes.fromhex(shared_key)
            challenge_bytes = bytes.fromhex(challenge)
            challenge_hash = HMAC.new(shared_key_bytes, challenge_bytes, digestmod=SHA512).digest()
            encrypted_challenge_hash = sdutils.pgp_encrypt_and_sign_data(challenge_hash.hex(), sender_public_key)
            client_socket.send(encrypted_challenge_hash)
            
            command = sdutils.pgp_encrypt_and_sign_data("SYNC_CONTACTS", sender_public_key)
            client_socket.send(command)
            
            client_socket.send(sdutils.pgp_encrypt_and_sign_data(sdutils._username, sender_public_key))
            client_socket.send(sdutils.pgp_encrypt_and_sign_data(sdutils._email, sender_public_key))
            
            encrypted_server_name = client_socket.recv(1024)
            encrypted_server_email = client_socket.recv(1024)
            if encrypted_server_name is None or encrypted_server_email is None:
                logger.warning(f"Failed to receive server name and email from {server}")
                continue
            
            server_name = sdutils.pgp_decrypt_and_verify_data(encrypted_server_name, sender_public_key)
            server_email = sdutils.pgp_decrypt_and_verify_data(encrypted_server_email, sender_public_key)
            
            if server_name == "CONTACT_MISMATCH" or server_email == "CONTACT_MISMATCH":
                logger.warning(f"Server {server} has a contact mismatch")
                continue
            
            with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
                data = sdutils.decrypt_and_verify(file.read())
                if data is None:
                    logger.warning("Failed to decrypt and verify contacts data")
                    continue
                
                if isinstance(data, dict):
                    data = json.dumps(data).encode('utf-8')
                
                data = json.loads(data.decode("utf-8"))
                contacts = data["contacts"]
            for contact in contacts:
                if contact["name"].lower() == server_name.lower() and contact["email"].lower() == server_email.lower():
                    contact["online"] = True
            
            with open(sdutils.CONTACTS_JSON_PATH, "wb") as file:
                file.write(sdutils.encrypt_and_sign(json.dumps({"contacts": contacts}).encode("utf-8")))
                
            client_socket.close()
        except Exception as e:
            logger.error(f"Failed to sync contacts: {e}")
            client_socket.close()
            continue
    
def add_contact() -> None:
    """
    Adds a new contact to the contacts list.
    Prompts the user to enter the full name and email address of the new contact.
    The contact is then added to the contacts list stored in a JSON file, which is
    encrypted and signed for security.
    The function performs the following steps:
    1. Initializes SecureDropUtils.
    2. Verifies the contact file.
    3. Prompts the user for the contact's full name and email address.
    4. Decrypts and verifies the existing contacts JSON file.
    5. Adds the new contact to the contacts list.
    6. Encrypts and signs the updated contacts list and writes it back to the file.
    7. Logs the addition of the new contact.
    If an error occurs during any of these steps, an error message is printed,
    the exception is logged, and the program exits.
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
    Lists the contacts from the SecureDrop contacts file, displaying them as online or offline.
    This function performs the following steps:
    1. Initializes the SecureDropUtils instance.
    2. Verifies the contact file.
    3. Synchronizes the contacts.
    4. Opens and reads the encrypted contacts JSON file.
    5. Decrypts and verifies the file content.
    6. Parses the JSON data to extract contacts.
    7. Prints the list of online and offline contacts.
    If any error occurs during these steps, it catches the exception, prints an error message, and exits the program.
    Raises:
        ValueError: If decryption and verification of the contacts file fail.
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
                
        print("\n  The following contacts are offline:")
        for contact in contacts:
            if not contact["online"]:
                print(f"  - {contact['name']} <{contact['email']}>")
    except Exception as e:
        print("An error occurred while listing the contacts.")
        print("Exception:", e)
        sys.exit()

def send_file(email: str, path: str) -> None:
    """
    Sends a file to a list of discovered servers using a secure connection.
    This function performs the following steps:
    1. Synchronizes contacts.
    2. Discovers servers.
    3. Establishes a secure SSL connection with each server.
    4. Authenticates the server using its public key.
    5. Exchanges and verifies a shared secret key.
    6. Sends a challenge to the server and verifies the response.
    7. Sends the command to send a file.
    8. Encrypts and sends the username and email.
    9. Verifies the server's username and email.
    10. Encrypts and sends the file name.
    11. Encrypts and sends the file data if the server's contact information matches.
    Args:
        email (str): The email address to send the file to.
        path (str): The file path of the file to be sent.
    Raises:
        ValueError: If decryption and verification of contacts data fails.
        Exception: If any other error occurs during the process.
    """
    sdutils = SecureDropUtils()

    sync_contacts()
    servers = _discover_servers()
    
    for server in servers:
        SERVER_PORT = 23325
        try:
            client_socket = socket.socket()
            client_socket.connect((server[0], SERVER_PORT))
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.verify_mode = ssl.CERT_REQUIRED
            with tempfile.NamedTemporaryFile() as private_key_file:
                private_key_file.write(sdutils._private_key.export_key())
                private_key_file.flush()
                private_key_file.seek(0)
                context.load_cert_chain(certfile=sdutils.CLIENT_CERT_PATH, keyfile=private_key_file.name)
            context.load_verify_locations(sdutils.CA_CERT_PATH)
            client_socket = context.wrap_socket(client_socket, server_hostname="SecureDrop")
                    
            cryptography_server_cert_der = client_socket.getpeercert(binary_form=True)
            cryptography_server_cert = x509.load_der_x509_certificate(cryptography_server_cert_der, default_backend())
            cryptography_server_public_key = cryptography_server_cert.public_key()
            if cryptography_server_public_key is None:
                logger.warning(f"Failed to get public key from {server}")
                continue
            sender_public_key_bytes = cryptography_server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sender_public_key = RSA.import_key(sender_public_key_bytes)
            
            encrypted_shared_secret_key = client_socket.recv(1024)
            if encrypted_shared_secret_key is None:
                logger.warning(f"Failed to receive shared key from {server}")
                continue
            shared_key = sdutils.pgp_decrypt_and_verify_data(encrypted_shared_secret_key, sender_public_key)
            if shared_key is None:
                logger.warning(f"Failed to decrypt and verify shared key from {server}")
                continue
            
            encrypted_challenge = client_socket.recv(1024)
            if encrypted_challenge is None:
                logger.warning(f"Failed to receive challenge from {server}")
                continue
            challenge = sdutils.pgp_decrypt_and_verify_data(encrypted_challenge, sender_public_key)
            if challenge is None:
                logger.warning(f"Failed to decrypt and verify challenge from {server}")
                continue
            
            shared_key_bytes = bytes.fromhex(shared_key)
            challenge_bytes = bytes.fromhex(challenge)
            challenge_hash = HMAC.new(shared_key_bytes, challenge_bytes, digestmod=SHA512).digest()
            encrypted_challenge_hash = sdutils.pgp_encrypt_and_sign_data(challenge_hash.hex(), sender_public_key)
            client_socket.send(encrypted_challenge_hash)
            
            command = sdutils.pgp_encrypt_and_sign_data("SEND_FILE", sender_public_key)
            client_socket.send(command)
            
            encrypted_username = sdutils.pgp_encrypt_and_sign_data(sdutils._username, sender_public_key)
            encrypted_email = sdutils.pgp_encrypt_and_sign_data(sdutils._email, sender_public_key)
            client_socket.send(encrypted_username)
            client_socket.send(encrypted_email)
            
            encrypted_server_username = client_socket.recv(1024)
            encrypted_server_email = client_socket.recv(1024)
            server_email = sdutils.pgp_decrypt_and_verify_data(encrypted_server_email, sender_public_key)
            server_username = sdutils.pgp_decrypt_and_verify_data(encrypted_server_username, sender_public_key)
            
            file_name = os.path.basename(path)
            encrypted_file_name = sdutils.pgp_encrypt_and_sign_data(file_name, sender_public_key)
            client_socket.send(encrypted_file_name)
            
            if server_username == "CONTACT_MISMATCH" or server_email == "CONTACT_MISMATCH":
                logger.warning(f"Server {server} has a contact mismatch")
                continue
            
            with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
                contacts_data = sdutils.decrypt_and_verify(file.read())
                if contacts_data is None:
                    raise ValueError("Decryption and verification failed.")
                contacts_data = json.loads(contacts_data.decode("utf-8"))
                contacts = contacts_data["contacts"]
            
            for contact in contacts:
                if contact["name"].lower() == server_username.lower() and contact["email"].lower() == server_email.lower():
                    with open(path, "r") as file:
                        data = file.read()
                    encrypted_data = sdutils.pgp_encrypt_and_sign_data(data, sender_public_key)
                    client_socket.send(encrypted_data)
                    break
            
            client_socket.close()
                        
        except Exception as e:
            logger.error(f"Failed to send file: {e}")
            client_socket.close()
            continue

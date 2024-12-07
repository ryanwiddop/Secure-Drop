import socket, ssl, threading, logging, tempfile, os, sys, signal, json
from secure_drop_utils import SecureDropUtils
from contacts import _verify_contact_file
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Crypto.Hash import SHA512
from Crypto.Hash import HMAC

shutdown_event = threading.Event()

def signal_handler(signum, frame):
    shutdown_event.set()

def handle_client(conn, addr):
    """
    Handles the client connection, performs SSL handshake, exchanges encrypted data,
    verifies the challenge response, and processes commands from the client.

    Args:
        conn (socket.socket): The client connection socket.
        addr (tuple): The client address.
        context (ssl.SSLContext): The SSL context for wrapping the socket.
    """
    try:
        _verify_contact_file()
        sdutils = SecureDropUtils()
        
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        with tempfile.NamedTemporaryFile() as private_key_file:
            private_key_file.write(sdutils._private_key.export_key())
            private_key_file.flush()
            private_key_file.seek(0)
            context.load_cert_chain(certfile=sdutils.CLIENT_CERT_PATH, keyfile=private_key_file.name)
        context.load_verify_locations(cafile=sdutils.CA_CERT_PATH)
        conn = context.wrap_socket(conn, server_side=True)

        cryptography_sender_cert = conn.getpeercert(binary_form=True)
        cryptography_sender_cert = x509.load_der_x509_certificate(cryptography_sender_cert, default_backend())
        cryptography_sender_public_key = cryptography_sender_cert.public_key()
        sender_public_key_bytes = cryptography_sender_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sender_public_key = RSA.import_key(sender_public_key_bytes)

        # Send IP address to client
        # response = conn.getsockname()[0]
        # encrypted_response = sdutils.pgp_encrypt_and_sign_data(response, sender_public_key)
        # conn.sendall(encrypted_response)

        # Generate shared secret key
        shared_secret_key = get_random_bytes(32)
        encrypted_shared_secret_key = sdutils.pgp_encrypt_and_sign_data(shared_secret_key.hex(), sender_public_key)
        conn.sendall(encrypted_shared_secret_key)

        # Verify challenge response
        challenge = get_random_bytes(32)
        encrypted_challenge = sdutils.pgp_encrypt_and_sign_data(challenge.hex(), sender_public_key)
        conn.sendall(encrypted_challenge)
        
        encrypted_signed_challenge = conn.recv(1024)
        signed_challenge_hex = sdutils.pgp_decrypt_and_verify_data(encrypted_signed_challenge, sender_public_key)
        signed_challenge = bytes.fromhex(signed_challenge_hex)

        try:
            h = HMAC.new(shared_secret_key, challenge, SHA512)
            h.verify(signed_challenge)
        except ValueError:
            logger.warning(f"Failed to verify challenge response from {addr}")
            conn.close()
            return
        
        # Receive command
        encrypted_command = conn.recv(1024)
        command = sdutils.pgp_decrypt_and_verify_data(encrypted_command, sender_public_key)
        logger.info(f"Received command {command} from {addr}")
        
        if command is None:
            logger.warning(f"Failed to decrypt and verify data from {addr} or invalid command received")
            conn.close()
            return
        elif command == "SYNC_CONTACTS":
            encrypted_sender_username = conn.recv(1024)
            encrypted_sender_email = conn.recv(1024)
            sender_username = sdutils.pgp_decrypt_and_verify_data(encrypted_sender_username, sender_public_key)
            sender_email = sdutils.pgp_decrypt_and_verify_data(encrypted_sender_email, sender_public_key)
            
            with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
                data = sdutils.decrypt_and_verify(file.read())
                if data is None:
                    logger.warning("Failed to decrypt and verify contacts data")
                
                if isinstance(data, dict):
                    data = json.dumps(data).encode('utf-8')
                
                data = json.loads(data.decode("utf-8"))
                contacts = data["contacts"]
                
            if not contacts:
                encrypted_username = sdutils.pgp_encrypt_and_sign_data("CONTACT_MISMATCH", sender_public_key)
                encrypted_email = sdutils.pgp_encrypt_and_sign_data("CONTACT_MISMATCH", sender_public_key)
                conn.sendall(encrypted_username)
                conn.sendall(encrypted_email)
            else:
                contact_found = False
                for contact in contacts:
                    if contact["name"] == sender_username and contact["email"] == sender_email:
                        encrypted_username = sdutils.pgp_encrypt_and_sign_data(sdutils._username, sender_public_key)
                        encrypted_email = sdutils.pgp_encrypt_and_sign_data(sdutils._email, sender_public_key)
                        conn.sendall(encrypted_username)
                        conn.sendall(encrypted_email)
                        contact_found = True
                        break
                    
                if not contact_found:
                    encrypted_username = sdutils.pgp_encrypt_and_sign_data("CONTACT_MISMATCH", sender_public_key)
                    encrypted_email = sdutils.pgp_encrypt_and_sign_data("CONTACT_MISMATCH", sender_public_key)
                    conn.sendall(encrypted_username)
                    conn.sendall(encrypted_email)

        elif command == "SEND_FILE":
            encrypted_sender_username = conn.recv(1024)
            encrypted_sender_email = conn.recv(1024)
            sender_username = sdutils.pgp_decrypt_and_verify_data(encrypted_sender_username, sender_public_key)
            sender_email = sdutils.pgp_decrypt_and_verify_data(encrypted_sender_email, sender_public_key)
            
            with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
                data = sdutils.decrypt_and_verify(file.read())
                if data is None:
                    logger.warning("Failed to decrypt and verify contacts data")
                
                if isinstance(data, dict):
                    data = json.dumps(data).encode('utf-8')
                
                data = json.loads(data.decode("utf-8"))
                contacts = data["contacts"]
                
            if not contacts:
                encrypted_username = sdutils.pgp_encrypt_and_sign_data("CONTACT_MISMATCH", sender_public_key)
                encrypted_email = sdutils.pgp_encrypt_and_sign_data("CONTACT_MISMATCH", sender_public_key)
                conn.sendall(encrypted_username)
                conn.sendall(encrypted_email)
            else:
                contact_found = False
                for contact in contacts:
                    if contact["name"] == sender_username and contact["email"] == sender_email:
                        encrypted_username = sdutils.pgp_encrypt_and_sign_data(sdutils._username, sender_public_key)
                        encrypted_email = sdutils.pgp_encrypt_and_sign_data(sdutils._email, sender_public_key)
                        conn.sendall(encrypted_username)
                        conn.sendall(encrypted_email)
                        contact_found = True
                        break
                    
                if not contact_found:
                    encrypted_username = sdutils.pgp_encrypt_and_sign_data("CONTACT_MISMATCH", sender_public_key)
                    encrypted_email = sdutils.pgp_encrypt_and_sign_data("CONTACT_MISMATCH", sender_public_key)
                    conn.sendall(encrypted_username)
                    conn.sendall(encrypted_email)
            
            encrypted_file_name = conn.recv(1024)
            file_name = sdutils.pgp_decrypt_and_verify_data(encrypted_file_name, sender_public_key)
            
            encrypted_file = conn.recv(4096)
            file = sdutils.pgp_decrypt_and_verify_data(encrypted_file, sender_public_key)
            
            if file is None:
                logger.warning(f"Failed to decrypt and verify file from {addr}")
                conn.close()
                return
            
            with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
                data = sdutils.decrypt_and_verify(file.read())
                if data is None:
                    logger.warning("Failed to decrypt and verify contacts data")
                
                if isinstance(data, dict):
                    data = json.dumps(data).encode('utf-8')
                
                data = json.loads(data.decode("utf-8"))
                contacts = data["contacts"]
                
            if contacts:
                for contact in contacts:
                    if contact["name"] == sender_username and contact["email"] == sender_email:
                        try:
                            
                            with open(sdutils.INBOX_PATH + file_name, "wb") as file:
                                file.write(file)
                            break
                        except Exception as e:
                            logger.error(f"Failed to write file to inbox: {e}")
                            break
                else:
                    logger.warning(f"Contact not found in contacts list")
            else:
                logger.warning(f"Contacts list is empty")
                
        else:
            logger.warning(f"Invalid command received from {addr}")
        
    except ssl.SSLError as e:
        logger.error(f"SSL error occurred while handling client {addr}")
        logger.error(f"SSLError: {e}")
    except socket.error as e:
        logger.error(f"Socket error occurred while handling client {addr}")
        logger.error(f"SocketError: {e}")
    except ValueError as e:
        logger.error(f"Value error occurred while handling client {addr}")
        logger.error(f"ValueError: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while handling client {addr}")
        logger.error(f"Exception: {e}")
    finally:
        conn.close()
        return

def discovery_server():
    """
    Sets up a discovery server to listen for incoming broadcast messages from clients.
    """
    try:
        sdutils = SecureDropUtils()
        PORT = 23326
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client_socket.bind(("", PORT))
        own_ip = socket.gethostbyname(socket.gethostname())
        logger.info(f"Discovery server listening on port {PORT}")
        
        while True:
            try:
                data, addr = client_socket.recvfrom(1024)
                if addr[0] == own_ip:
                    pass
                logger.info(f"Dicovery request received from {addr}")
                if data == b"DISCOVER_SECURE_DROP":
                    cert = x509.load_pem_x509_certificate(open(sdutils.CLIENT_CERT_PATH, "rb").read(), default_backend())
                    response = cert.public_bytes(serialization.Encoding.PEM)
                    client_socket.sendto(response, addr)
                    logger.info(f"Sent certificate to {addr}")
                else:
                    logger.warning(f"Invalid discovery request received from {addr}")
            except KeyboardInterrupt:
                logger.info("Stopping discovery server...")
                break
            except Exception as e:
                logger.info(f"Stopping discovery server... {e}")
                break
        
        client_socket.close()
        logger.info("Discovery server stopped")
    except Exception as e:
        client_socket.close()
        logger.info("Discovery server stopped {e}")

def main():
    """
    Sets up the server socket, binds it to a port, listens for incoming connections,
    and spawns a new thread to handle each client connection.

    Uses SSL for secure communication and logs important events.
    """
    
    if len(sys.argv) != 2:
        print("Usage: secure_drop_server.py <socket_fd>")
        sys.exit()
    
    sock_fd = int(sys.argv[1])
    sock = socket.socket(fileno=sock_fd)
    
    private_key = sock.recv(4096).decode('utf-8').strip()
    encrypted_username = sock.recv(4096).decode('utf-8').strip()
    encrypted_email = sock.recv(4096).decode('utf-8').strip()
    
    sock.close()
    
    sdutils = SecureDropUtils()
    
    sdutils._private_key = private_key
    with open(sdutils._PUBLIC_KEY_PATH, "rb") as file:
        sdutils._public_key = RSA.import_key(file.read())
    username = sdutils.decrypt_and_verify(encrypted_username)
    email = sdutils.decrypt_and_verify(encrypted_email)
    sdutils._username = username
    sdutils._email = email
    
    logging.basicConfig(
        filename=sdutils.LOG_FILE_PATH,
        level=logging.INFO,
        format="%(asctime)s SERVER | %(levelname)s: %(message)s"
    )
    global logger 
    logger = logging.getLogger()
    
    HOST = ""
    PORT = 23325
    
    discovery_server_thread = threading.Thread(target=discovery_server)
    discovery_server_thread.start()
    
    with socket.socket() as server_socket:
        server_socket.bind((HOST, PORT))
        
        server_socket.listen(5)
        logger.info(f"Secure Drop Server listening on port {PORT}...")
        
        while not shutdown_event.is_set():
            try:
                server_socket.settimeout(1.0)
                conn, addr = server_socket.accept()
                logger.info(f"Accepted connection from {addr}")
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.start()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
    
    logger.info("Secure Drop Server stopped")
    discovery_server_thread.join()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()
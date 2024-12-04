import socket, ssl, threading, logging
from secure_drop_utils import SecureDropUtils
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Crypto.Hash import SHA512
from Crypto.Hash import HMAC

def handle_client(conn, addr, context):
    """
    Handles the client connection, performs SSL handshake, exchanges encrypted data,
    verifies the challenge response, and processes commands from the client.

    Args:
        conn (socket.socket): The client connection socket.
        addr (tuple): The client address.
        context (ssl.SSLContext): The SSL context for wrapping the socket.
    """
    try:
        conn = context.wrap_socket(conn, server_side=True)
        sdutils = SecureDropUtils()
        
        cryptography_sender_cert = conn.getpeercert(binary_form=True)
        cryptography_sender_cert = x509.load_der_x509_certificate(cryptography_sender_cert, default_backend())
        cryptography_sender_public_key = cryptography_sender_cert.public_key()
        sender_public_key_bytes = cryptography_sender_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sender_public_key = RSA.import_key(sender_public_key_bytes)

        # Send IP address to client
        response = conn.getsockname()[0]
        encrypted_response = sdutils.pgp_encrypt_and_sign_data(response, sender_public_key)
        conn.sendall(encrypted_response)

        # Generate shared secret key
        shared_secret_key = get_random_bytes(32)
        encrypted_shared_secret_key = sdutils.pgp_encrypt_and_sign_data(shared_secret_key, sender_public_key)
        conn.sendall(encrypted_shared_secret_key)

        # Verify challenge response
        challenge = get_random_bytes(32)
        encrypted_challenge = sdutils.pgp_encrypt_and_sign_data(challenge, sender_public_key)
        conn.sendall(encrypted_challenge)
        
        encrypted_signed_challenge = conn.recv(1024)
        signed_challenge = sdutils.pgp_decrypt_and_verify_data(encrypted_signed_challenge, sender_public_key)
        
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
        
        if command is None:
            logger.warning(f"Failed to decrypt and verify data from {addr}")
            conn.close()
            return
        elif command == b"SYNC_CONTACTS":
            pass
        elif command == b"SEND_FILE":
            pass
        
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
    
def main():
    """
    Sets up the server socket, binds it to a port, listens for incoming connections,
    and spawns a new thread to handle each client connection.

    Uses SSL for secure communication and logs important events.
    """
    sdutils = SecureDropUtils()
    
    logging.basicConfig(
        filename=sdutils.SERVER_LOG_PATH,
        level=logging.INFO,
        format="%(asctime)s SERVER | %(levelname)s: %(message)s"
    )
    global logger 
    logger = logging.getLogger()
    
    HOST = ""
    PORT = 23325
    
    server_socket = socket.socket()
    server_socket.bind((HOST, PORT))
    logger.info(f"Socket bound to port {PORT}")
    
    server_socket.listen(5)
    logger.info("Socket is listening...")
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=sdutils.CLIENT_CERT_PATH, keyfile=sdutils.CLIENT_KEY_PATH)
    
    while True:
        try:
            conn, addr = server_socket.accept()
            logger.info(f"Accepted connection from {addr}")
            client_thread = threading.Thread(target=handle_client, args=(conn, addr, context))
            client_thread.start()
        except KeyboardInterrupt:
            logger.info("Closing socket...")
            server_socket.close()
            break
    
    logger.info("Socket closed")
        
if __name__ == "__main__":
    main()
import sys, subprocess, logging, socket, os
from registration import startup
from contacts import add_contact, list_contacts, send_file
from secure_drop_utils import SecureDropUtils
from pathlib import Path

def start_secure_drop_server() -> tuple:
    sdutils = SecureDropUtils()
    private_key = sdutils._private_key.export_key()
    username = sdutils._username
    email = sdutils._email
    server_path = str(Path(__file__).parent / "secure_drop_server.py")
    
    parent_sock, child_sock = socket.socketpair()
    
    process = subprocess.Popen(
        ["python3", server_path, str(child_sock.fileno())],
        pass_fds=(child_sock.fileno(),),
        text=True
    )
            
    encrypted_username = sdutils.pgp_encrypt_and_sign_data(username, sdutils._public_key)
    encrypted_email = sdutils.pgp_encrypt_and_sign_data(email, sdutils._public_key)
    
    parent_sock.sendall(private_key + b"---END---")
    parent_sock.sendall(encrypted_username + b"---END---")
    parent_sock.sendall(encrypted_email)
    
    return process, parent_sock

def secure_drop_shell():
    process = None
    sock = None
    try:
        sdutils = SecureDropUtils()
        
        process, sock = start_secure_drop_server()
        print("Welcome to Secure Drop.\nType \"help\" For Commands.\n")
        
        while True:
            command = input("secure_drop> ")
            if command == "help":
                print("  \"add\" -> Add a new contact")
                print("  \"list\" -> List all online contacts")
                print("  \"send\" -> Transfer file to contact")
                print("  \"exit\" -> Exit SecureDrop")
            elif command.lower() == "add":
                add_contact()
            elif command.lower() == "list":
                list_contacts()
            elif command.startswith("send"):
                args = command.split(" ")
                if not len(args) == 3:
                    print("  Invalid number of arguments.")
                    continue
                if not os.path.exists(args[2]):
                    print("  File does not exist.")
                    continue
                
                send_file(args[1], args[2])
                pass
            elif command == "exit":
                break
            elif command == "y":
                try:
                    sock.sendall(b"y")
                except BrokenPipeError as e:
                    print("Error: Broken pipe. The server may have terminated unexpectedly.")
                    print("Exception:", e)
                    break
                except Exception as e:
                    print("An error occurred.")
                    print("Exception:", e)
    except SystemExit:
        pass
    except Exception as e:
        print("An error occurred.")
        print("Exception:", e)
    finally:
        if process:
            process.kill()
            process.wait()
        if sock:
            sock.close()

def main():
    sdutils = SecureDropUtils()
    
    logging.basicConfig(
        filename=sdutils.LOG_FILE_PATH,
        level=logging.INFO,
        format="%(asctime)s CLIENT | %(levelname)s: %(message)s"
    )
    logger = logging.getLogger()    
    try:
        startup()
    except KeyboardInterrupt:
        print("\nExiting SecureDrop.")
        logger.info("Exiting SecureDrop.")
        logger.info("-" * 50)
        exit()
    except SystemExit:
        print("\nExiting SecureDrop.")
        logger.info("Exiting SecureDrop.")
        logger.info("-" * 50)
        exit()
    
    try:
        logger.info("SecureDrop started.")
        secure_drop_shell()
    except KeyboardInterrupt:
        print("\nExiting SecureDrop.")
        logger.info("Exiting SecureDrop.")
        logger.info("-" * 50)
        exit()
    except SystemExit:
        logger.info("Exiting SecureDrop.")
        logger.info("-" * 50)
        exit()
    except Exception as e:
        print("An error occurred.")
        print("Exception:", e)
        logger.error(f"An error occurred: {e}")
        logger.info("Exiting SecureDrop.")
        logger.info("-" * 50)
        exit()
        
if __name__ == "__main__":
    main()

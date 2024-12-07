import sys, subprocess, logging, socket
from registration import startup
from contacts import add_contact, list_contacts, send_file
from secure_drop_utils import SecureDropUtils
from pathlib import Path

def start_secure_drop_server() -> subprocess.Popen:
    sdutils = SecureDropUtils()
    private_key = sdutils._private_key.export_key().decode("utf-8")
    username = sdutils._username
    email = sdutils._email
    server_path = str(Path(__file__).parent / "secure_drop_server.py")
    
    parent_sock, child_sock = socket.socketpair()
    
    process = subprocess.Popen(
        ["python3", server_path, str(child_sock.fileno())],
        pass_fds=(child_sock.fileno(),),
        text=True
    )
    
    child_sock.close()
        
    encrypted_username = sdutils.encrypt_and_sign(username.encode("utf-8"))
    encrypted_email = sdutils.encrypt_and_sign(email.encode("utf-8"))
    
    parent_sock.sendall(private_key.encode('utf-8') + b'\n')
    parent_sock.sendall(encrypted_username + b'\n')
    parent_sock.sendall(encrypted_email + b'\n')
    
    parent_sock.close()
    return process

def secure_drop_shell():
    process = None
    try:
        sdutils = SecureDropUtils()
        
        process = start_secure_drop_server()
        print("Welcome to Secure Drop.\nType \"help\" For Commands.\n")
        
        while True:
            command = input("secure_drop> ")
            if command == "help":
                print("  \"add\" -> Add a new contact")
                print("  \"list\" -> List all online contacts")
                print("  \"send\" -> Transfer file to contact")
                print("  \"exit\" -> Exit SecureDrop")
            elif command == "add":
                add_contact()
            elif command == "list":
                list_contacts()
            elif command.startswith("send"):
                args = command.split(" ")
                if not len(args) == 3:
                    print("  Invalid number of arguments.")
                    continue
                send_file(args[1], args[2])
                pass
            elif command == "exit":
                break
    except SystemExit:
        pass
    except Exception as e:
        print("An error occurred.")
        print("Exception:", e)
    finally:
        if process:
            process.kill()
            process.wait()

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

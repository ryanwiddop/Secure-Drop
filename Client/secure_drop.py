import sys, subprocess, logging
from registration import startup
from contacts import add_contact, list_contacts
from secure_drop_utils import SecureDropUtils
from pathlib import Path

def start_secure_drop_server() -> subprocess.Popen:
    sdutils = SecureDropUtils()
    server_path = str(Path(__file__).parent / "secure_drop_server.py")
    private_key = sdutils._private_key.export_key().decode("utf-8")
    
    process = subprocess.Popen(
        ["python3", server_path],
        stdin=subprocess.PIPE,
        text=True
    )
    process.stdin.write(private_key)
    process.stdin.write(sdutils._username)
    process.stdin.write("\n")
    process.stdin.write(sdutils._email)
    process.stdin.close()
    return process

def secure_drop_shell():
    process = None
    try:
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
            elif command == "send":
                # UDP or !TLS!
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

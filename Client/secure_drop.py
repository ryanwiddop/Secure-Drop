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
    process.stdin.write("\n")
    process.stdin.write(sdutils._username)
    process.stdin.write("\n")
    process.stdin.write(sdutils._email)
    process.stdin.close()
    return process

def secure_drop_shell():
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
            sys.exit()


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
        print("\nExiting Secure Drop.")
        logger.info("Exiting Secure Drop.")
        logger.info("-" * 50)
        exit()
    except SystemExit:
        print("\nExiting Secure Drop.")
        logger.info("Exiting Secure Drop.")
        logger.info("-" * 50)
        exit()
    
    try:
        process = start_secure_drop_server()
    except SystemExit:
        exit()
    except Exception as e:
        print("An error occurred.")
        print("Exception:", e)
        exit()
    
    try:
        logger.info("Secure Drop started.")
        secure_drop_shell()
    except KeyboardInterrupt:
        print("\nExiting Secure Drop.")
        logger.info("Exiting Secure Drop.")
        logger.info("-" * 50)
        process.terminate()
        exit()
    except SystemExit:
        process.terminate()
        logger.info("Exiting Secure Drop.")
        logger.info("-" * 50)
        exit()
    except Exception as e:
        process.terminate()
        print("An error occurred.")
        print("Exception:", e)
        logger.error(f"An error occurred: {e}")
        logger.info("Exiting Secure Drop.")
        logger.info("-" * 50)
        exit()
        
if __name__ == "__main__":
    main()

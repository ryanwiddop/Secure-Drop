import json, sys, os, logging
from getpass import getpass
from Crypto.PublicKey import RSA
from secure_drop_utils import SecureDropUtils
from pathlib import Path

logger = logging.getLogger()

def _get_registered_user() -> bool:
    """
    Checks if a registered user exists by reading and validating the user data from a file.
    The function attempts to read the user data from a file specified by USER_JSON_PATH.
    It checks if the data starts with the string "ENCRYPTED\n" and if the length of the data
    is greater than 9 bytes. If these conditions are met, it returns True indicating that
    a registered user exists. Otherwise, it returns False.
    Returns:
        bool: True if a registered user exists, False otherwise.
    Exceptions:
        KeyError: If a KeyError occurs during file operations.
        FileNotFoundError: If the file specified by USER_JSON_PATH is not found.
        json.JSONDecodeError: If there is an error decoding JSON from the file.
        SystemExit: If a JSON decoding error occurs, the program will exit.
        Exception: If any other exception occurs, it prints the exception and returns None.
    """
    try:
        sdutils = SecureDropUtils()
        try:
            with open(sdutils.USER_JSON_PATH, "rb") as file:
                data = file.read()
            if not data.startswith(b"ENCRYPTED\n") or len(data) <= 9:
                return False
        
        except KeyError:
            return False
        except FileNotFoundError:
            return False
        except json.JSONDecodeError:
            print("Error decoding JSON from the file.")
            sys.exit()
        return True
    except:
        print("Error getting registered user.")
        print("Exception: ", sys.exc_info()[0])
        return None

def _register_new_user(username: str, email: str, password: str) -> None:
    """
    Registers a new user by hashing the password, encrypting the user data, 
    and saving it to a file.

    Args:
        username (str): The username of the new user.
        email (str): The email address of the new user.
        password (str): The password of the new user.

    Raises:
        Exception: If an error occurs during the registration process.
    """
    try:
        os.makedirs(str(Path(__file__).parent / ".db/"), exist_ok=True)  

        sdutils = SecureDropUtils()
        new_user = {
            "username": username,
            "email": email,
            "password": sdutils.hash_data(password)
        }
        
        with open(sdutils._PRIVATE_KEY_PATH, "rb") as file:
            sdutils._private_key = RSA.import_key(file.read())
        with open(sdutils._PUBLIC_KEY_PATH, "rb") as file:
            sdutils._public_key = RSA.import_key(file.read())
        
        new_user_encrypted = sdutils.encrypt_and_sign(json.dumps(new_user).encode("utf-8"))
        with open(sdutils.USER_JSON_PATH, "wb") as file:
            file.write(new_user_encrypted)
    except Exception as e:
        print("Error registering new user.")
        print("Exception: ", e)
        sys.exit()
            
def _verify_user(email: str, password: str) -> bool: 
    """
    Verifies the user"s email and password.
    This function attempts to verify a user"s email and password by decrypting
    and verifying the stored user data. If the verification is successful, it
    sets the user information in the system.
    Args:
        email (str): The email address of the user.
        password (str): The password of the user.
    Returns:
        bool: True if the user is successfully verified, False otherwise.
    Raises:
        FileNotFoundError: If the user data file is not found.
        json.JSONDecodeError: If there is an error decoding the JSON data.
        Exception: For any other exceptions that occur during verification.
    """
    try:
        sdutils = SecureDropUtils()
        try:
            if not sdutils.decrypt_private_key(password):
                return False
            
            with open(sdutils.USER_JSON_PATH, "rb") as file:
                encrypted_data = file.read()

                user_data = sdutils.decrypt_and_verify(encrypted_data)
                if user_data is None:
                    print("Decryption and verification of user data failed.")
                    return False
                user = json.loads(user_data.decode("utf-8"))
            
            if user["email"] == email and sdutils.verify_hash(password, user["password"]):
                sdutils._username = user["username"]
                sdutils._email = user["email"]
                return True
            else:
                return False
        except FileNotFoundError:
            print(f"File not found: {sdutils.USER_JSON_PATH}")
            sys.exit()
        except json.JSONDecodeError:
            print("Error decoding JSON from the file.")
            sys.exit()
    except Exception as e:
        print("Error verifying user")
        print("Exception:", e)
        return False
                 
def startup() -> None:
    """
    Handles the startup process for the SecureDrop client.
    This function performs the following steps:
    1. Verifies the key pair using `sdutils.verify_key_pair()`.
    2. Checks if there are any registered users.
       - If no users are registered, prompts the user to register a new user.
         - Collects the user"s full name, email address, and password.
         - Ensures the password and re-entered password match.
         - Registers the new user and encrypts the private key with the password.
         - Exits the program after registration.
       - If users are already registered, prompts the user to log in.
         - Collects the user"s email address and password.
         - Verifies the user"s credentials.
         - If the credentials are invalid, prompts the user to re-enter them.
         - If the credentials are valid, welcomes the user.
    If an error occurs during the startup process (excluding SystemExit), 
    it prints an error message and the exception type, then exits the program.
    Raises:
        SystemExit: Exits the program in various scenarios.
    """
    try:
        sdutils = SecureDropUtils()

        if not _get_registered_user():
            sdutils.verify_key_pair()
            print("No users are registered with this client.")
            if(input("Do you want to register a new user (y/n)? ") == "y"):
                name = input("Enter Full Name: ")
                email = input("Enter Email Address: ")
                password = getpass("Enter Password: ")
                repassword = getpass("Re-enter Password: ")
                while (password != repassword):
                    print("\nPasswords do not match!")
                    password = getpass("Enter Password: ")
                    repassword = getpass("Re-enter Password: ")
                else:
                    print("\nPasswords Match.")
                _register_new_user(name, email, password)
                
                logging.info("User Registered")
                print("User Registered\n")
                sdutils.encrypt_private_key(password)
                
                password = None
                repassword = None
                
                sys.exit()
            else:
                sys.exit()
        else:
            email = input("Enter Email Address: ")
            password = getpass("Enter Password: ")
                                
            while (not _verify_user(email, password)):
                print("Email and Password Combination Invalid.\n")
                email = input("Enter Email Address: ")
                password = getpass("Enter Password: ")
            print("Username and Password verified. Welcome.")
            logging.info("User Verified")
            password = None
    except Exception as e:
        print("An error occurred during startup.")
        print("Exception:", e)
        logging.error(f"An error occurred during startup: {e}")
        sys.exit()
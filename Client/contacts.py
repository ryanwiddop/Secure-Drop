from secure_drop_utils import SecureDropUtils
import os, json, sys, socket

def __verify_contact_file() -> None:
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

def sync_contacts(contacts):
    PORT = 12345
    client_socket = socket.socket()
    client_socket.connect(('localhost', PORT))
    
    print(client_socket.recv(1024).decode("utf-8"))
    
    client_socket.close() 
        
    return contacts
    
def add() -> None:
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
        
        __verify_contact_file()
        name = input("  Enter Full Name: ")
        email = input("  Enter Email Address: ")
        new_contact = {
            "name": name,
            "email": email
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
    except Exception as e:
        print("An error occurred while adding the contact.")
        print("Exception:", e)
        sys.exit()

def list() -> None:
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
        __verify_contact_file()
        with open(sdutils.CONTACTS_JSON_PATH, "rb") as file:
            data = sdutils.decrypt_and_verify(file.read())
            if data is None:
                raise ValueError("Decryption and verification failed.")
            data = json.loads(data.decode("utf-8"))
            contacts = data["contacts"]
        contacts = sync_contacts(contacts)
        print("  The following contacts are online:")
        for contact in contacts:
            if contact["online"]:
                print(f"  * {contact['name']} <{contact['email']}>")
    except Exception as e:
        print("An error occurred while listing the contacts.")
        print("Exception:", e)
        sys.exit()

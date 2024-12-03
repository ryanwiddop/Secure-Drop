import sys, subprocess
from registration import startup
from contacts import add, list

def start_secure_drop_server():
    with open("server.log", "w") as file:
        file.write("Server starting.\n")
    with open("server.log", "a") as file:
        process = subprocess.Popen(["python3", "secure_drop_server.py"], stdout=file, stderr=file)
        file.write("Server started.\n")
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
            add()
        elif command == "list":
            list()
        elif command == "send":
            # UDP or !TLS!
            pass
        elif command == "exit":
            sys.exit()


def main():
    try:
        startup()
    except SystemExit:
        exit()
    
    try:
        start_secure_drop_server()
    except SystemExit:
        exit()
    except Exception as e:
        print("An error occurred.")
        print("Exception:", e)
        exit()
    
    try:
        secure_drop_shell()
    except SystemExit:
        exit()
    except Exception as e:
        print("An error occurred.")
        print("Exception:", e)
        exit()
        
        

if __name__ == "__main__":
    main()

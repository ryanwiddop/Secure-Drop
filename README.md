# Project Documentation Checklist

## Source Code

- [x] Combine all your source files into a single zip file named `source.zip`.
- [x] Include a `requirements.txt` file within the zip, listing all the Python packages utilized.

## Screenshots

- [x] Compile a `screenshots.pdf` file displaying screenshots of successfully executed milestones.

## Security Overview

- [x] Assemble a `security.pdf` file with brief paragraphs addressing the security aspects of each milestone.

  - Provide high-level insights, as detailed discussions will be covered during the presentation.

## Contributions Summary

- [x] Prepare a `contributions.pdf` file that explicitly outlines the contributions of each team member.

  - Specify the tasks undertaken by each team member.
  - Assign a percentage (out of 100%) to denote each team member's contribution.

## Security Workflow per Milestone (detailed)

## Milestone 1 - User Registration

1. The user is prompted for a username, email, and password.
2. The python module getpass is used to hide the password as it is typed.
3. A salt is generated, then the password is hashed with the salt.
4. The username, email, and salted hashed password is stored in a json file.
5. The private key is encrypted using the password:
    1. A 16 byte salt is generated
    2. A key is derived from the password using PBKDF2 (Password-Based Key Derivation Function 2).
        - SHA512
        - 1,000,000 iterations
    3. The private key is encrypted using AES in EAX mode.
    4. The salt, nonce, tag, and ciphertext are put into a byte structure and written over the unencrypted private key
6. The user json file is encrypted and written
    > Steps for all local encryption:
    1. A 32 byte session key is generated
    2. The data is encrypted with the session key, using AES in EAX mode
    3. The session key is encrypted with RSA (PKCS#1 OAEP (Optimal Asymmetric Encryption Padding))
    4. The data is used to generate a SHA512/256 (truncated to 256) hash.
    5. The hash is used to create a signature of the data using PKCS #1 v1.5 (Public-Key Cryptography Standards)
        - Drawback of PKCS #1 v1.5:
        It is deterministic. The same message and key will always produce the same signature value.
        RSA PSS is more complex to implement so PKCS #1 v1.5 was chosen.
    6. The session key, nonce, tag, ciphertext, and signature are packed into a bytes structure and written.

## Milestone 2 - User Login

1. The user is prompted for an email and password.
2. The python module getpass is used to hide the password as it is typed.
3. A key is derived from the entered password using PBKDF2 (SHA512)
4. The key is used to attempt to decrypt the private key, if decryption fails then the user is prompted for a new login combination
5. The private key is decrypted into memory
6. The user json file is decrypted with decrypted private key
7. The password is hashed using the read salt, and the hashes and emails are compared.

## Milestone 3 - Adding Contacts

1. The user is prompted for a name and email.
2. The contacts json is decrypted into memory
3. The new contact is added to the json structure
4. The json structure is encrypted and signed then written over the old file

## Milestone 4 - Listing Contacts

1. The user client syncs contacts with all available servers:
    Discovery (UDP):
    1. A UDP socket is created.
    2. A message "DISCOVER_SECURE_DROP" is broadcast to all machines on the subnet with port 23326 open
    3. The server sends back it's certificate
    4. The client verifies the integrity of the certificate using the ca certificate.
    5. All found servers with a valid certificate response are stored in a list.

    6. A TCP connection is made to each of the found servers over port 23325.
    7. The TCP socket is wrapped with an TLS context using the clients cert chain (cert and private key) and the ca cert.
    8. The server's cert is taken from the TLS.
    9. A pgp encrypted shared secret key and challenge is received from the server, which is decrypted up reception
    10. A challenge hash is created using HMAC (Hash-Based Message Authentication Code) with the shared secret key and challenge
    11. The challenge hash is pgp encrypted using the servers public key, then sent back.
    12. Assuming the server successfully verifies the challenge hash *(if not, the socket will be closed on the server side and the exception will be handled)*, then the command "SYNC_CONTACTS" is sent to the server.
    13. The client pgp encrypted and sends it's username and email
    14. If the client's username / email is not present in the server's contacts json file, then "CONTACT_MISMATCH" will be received from the server, if it is, the server will send back it's username and email
    15. If the user is online, their entry in the contacts json will be marked with online as true.
    16. Once all contacts are synced, all online contacts are printed.

## Milestone 5 - Secure File Transfer

1. The user sends a file securely to a server:
    1. The client synchronizes contacts to ensure server availability and online status.
    2. A list of servers is discovered on the network using UDP broadcast over port 23326.
    3. A TCP connection is established to each discovered server on port 23325.
    4. The TCP socket is wrapped in a TLS context using the client’s certificate chain (certificate and private key) and the CA certificate.
    5. The server’s public certificate is verified during the TLS handshake.
    6. A PGP-encrypted shared secret key and challenge are received from the server and decrypted by the client.
    7. A challenge hash is created using HMAC with the shared secret key and challenge.
    8. The challenge hash is PGP-encrypted with the server’s public key and sent back to the server.
    9. If the server successfully verifies the challenge hash *(or terminates the connection otherwise)*, the command "SEND_FILE" is sent to the server.
    10. The client’s username and email are encrypted using PGP and sent to the server.
    11. The server’s encrypted username and email are received, decrypted, and verified:
        - If there is a mismatch, the client logs "CONTACT_MISMATCH" and terminates the connection.
    12. The client encrypts and sends the file name using PGP.
    13. The file content is read and encrypted:
        - If the file is a text file, it is read as a string and encrypted.
        - If the file is binary, it is read in byte format and converted to a hexadecimal representation before encryption.
    14. The file size and file type (text or binary) are encrypted and sent to the server.
    15. The file is transmitted in encrypted chunks of 8 KB until the entire file has been sent.
    16. Once the file transfer is complete, the connection is gracefully closed.

# Project Documentation Checklist

## Source Code
- [ ] Combine all your source files into a single zip file named `source.zip`.
- [x] Include a `requirements.txt` file within the zip, listing all the Python packages utilized.

## Screenshots
- [ ] Compile a `screenshots.pdf` file displaying screenshots of successfully executed milestones.

## Security Overview
- [ ] Assemble a `security.pdf` file with brief paragraphs addressing the security aspects of each milestone.
    - Provide high-level insights, as detailed discussions will be covered during the presentation.

## Contributions Summary
- [ ] Prepare a `contributions.pdf` file that explicitly outlines the contributions of each team member.
    - Specify the tasks undertaken by each team member.
    - Assign a percentage (out of 100%) to denote each team member's contribution.

# Security Workflow per Milestone (detailed)
## Milestone 1 - User Registration:
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
    > All local encryption:
    1. A 32 byte session key is generated
    2. The data is encrypted with the session key, using AES in EAX mode
    3. The session key is encrypted with RSA (PKCS#1 OAEP (Optimal Asymmetric Encryption Padding))
    4. The data is used to generate a SHA512/256 (truncated to 256) hash.
    5. The hash is used to create a signature of the data using PKCS #1 v1.5 (Public-Key Cryptography Standards)
        - Drawback of PKCS #1 v1.5: 
        It is deterministic. The same message and key will always produce the same signature value.
    6. The session key, nonce, tag, ciphertext, and signature are packed into a bytes structure and written.

## Milestone 2 - User Login:
1. The user is prompted for an email and password.
2. The python module getpass is used to hide the password as it is typed.
3. A key is derived from the entered password using PBKDF2 (SHA512)
4. The key is used to attempt to decrypt the private key, if decryption fails then the user is prompted for a new login combination
5. The private key is decrypted into memory
6. The user json file is decrypted with decrypted private key
7. The password is hashed using the read salt, and the hashes and emails are compared.

## Milestone 3 - Adding Contacts:
1.
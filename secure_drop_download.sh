#!/bin/bash

# Variables
CONTACTS_URL="https://github.com/ryanwiddop/Secure-Drop/raw/refs/heads/main/Client/contacts.py"
REGISTRATION_URL="https://github.com/ryanwiddop/Secure-Drop/raw/refs/heads/main/Client/registration.py"
SECURE_DROP_URL="https://github.com/ryanwiddop/Secure-Drop/raw/refs/heads/main/Client/secure_drop.py"
SECURE_DROP_SERVER_URL="https://github.com/ryanwiddop/Secure-Drop/raw/refs/heads/main/Client/secure_drop_server.py"
SECURE_DROP_UTILS_URL="https://github.com/ryanwiddop/Secure-Drop/raw/refs/heads/main/Client/secure_drop_utils.py"
DEST_DIR="$(pwd)"
KEYS_DIR="$DEST_DIR/.keys"

# Create .keys directory if it doesn't exist
mkdir -p "$KEYS_DIR"

# Download Python files from the GitHub repository
wget -O contacts.py "$CONTACTS_URL"
wget -O registration.py "$REGISTRATION_URL"
wget -O secure_drop.py "$SECURE_DROP_URL"
wget -O secure_drop_server.py "$SECURE_DROP_SERVER_URL"
wget -O secure_drop_utils.py "$SECURE_DROP_UTILS_URL"

rm secure_drop_download.sh

echo "Download complete. Files saved to $DEST_DIR"
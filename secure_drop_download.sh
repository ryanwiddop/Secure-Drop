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

# Remove existing Python files
rm -f "$DEST_DIR"/contacts.py
rm -f "$DEST_DIR"/registration.py
rm -f "$DEST_DIR"/secure_drop.py
rm -f "$DEST_DIR"/secure_drop_server.py
rm -f "$DEST_DIR"/secure_drop_utils.py

wget --no-cache -O contacts.py "$CONTACTS_URL"
wget --no-cache -O registration.py "$REGISTRATION_URL"
wget --no-cache -O secure_drop.py "$SECURE_DROP_URL"
wget --no-cache -O secure_drop_server.py "$SECURE_DROP_SERVER_URL"
wget --no-cache -O secure_drop_utils.py "$SECURE_DROP_UTILS_URL"

echo "Download complete. Files saved to $DEST_DIR"
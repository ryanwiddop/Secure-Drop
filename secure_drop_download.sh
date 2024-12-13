#!/bin/bash

COMMANDS_URL="https://github.com/ryanwiddop/Secure-Drop/raw/refs/heads/main/Client/commands.py"
REGISTRATION_URL="https://github.com/ryanwiddop/Secure-Drop/raw/refs/heads/main/Client/registration.py"
SECURE_DROP_URL="https://github.com/ryanwiddop/Secure-Drop/raw/refs/heads/main/Client/secure_drop.py"
SECURE_DROP_SERVER_URL="https://github.com/ryanwiddop/Secure-Drop/raw/refs/heads/main/Client/secure_drop_server.py"
SECURE_DROP_UTILS_URL="https://github.com/ryanwiddop/Secure-Drop/raw/refs/heads/main/Client/secure_drop_utils.py"
DEST_DIR="$(pwd)"
KEYS_DIR="$DEST_DIR/.keys"

mkdir -p "$KEYS_DIR"

rm -f "$DEST_DIR"/commands.py
rm -f "$DEST_DIR"/registration.py
rm -f "$DEST_DIR"/secure_drop.py
rm -f "$DEST_DIR"/secure_drop_server.py
rm -f "$DEST_DIR"/secure_drop_utils.py

wget --no-cache -O contacts.py "$COMMANDS_URL"
wget --no-cache -O registration.py "$REGISTRATION_URL"
wget --no-cache -O secure_drop.py "$SECURE_DROP_URL"
wget --no-cache -O secure_drop_server.py "$SECURE_DROP_SERVER_URL"
wget --no-cache -O secure_drop_utils.py "$SECURE_DROP_UTILS_URL"

echo "Download complete. Files saved to $DEST_DIR"

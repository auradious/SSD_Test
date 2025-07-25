#!/bin/bash

# Start Gitea in the background
/usr/bin/entrypoint &
GITEA_PID=$!

# Wait for Gitea to be ready
echo "Waiting for Gitea to start..."
sleep 15

# Check if Gitea is responding
until curl -f http://localhost:3000 >/dev/null 2>&1; do
    echo "Waiting for Gitea to be ready..."
    sleep 5
done

echo "Gitea is ready, creating user..."

# Create the git123 user (only if it doesn't exist)
if ! gitea admin user list | grep -q "git123"; then
    echo "Creating user git123..."
    gitea admin user create --username git123 --password git123 --email git123@localhost --admin
    echo "User git123 created successfully"
else
    echo "User git123 already exists"
fi

# Wait for the background Gitea process
wait $GITEA_PID
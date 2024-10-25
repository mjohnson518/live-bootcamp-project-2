#!/bin/bash

# Define the location of the .env file
ENV_FILE="./auth-service/.env"

# Check if the .env file exists
if ! [[ -f "$ENV_FILE" ]]; then
    echo "Error: .env file not found!"
    exit 1
fi

# Read and export environment variables
while IFS= read -r line; do
    # Skip blank lines and lines starting with #
    if [[ -n "$line" ]] && [[ "$line" != \#* ]]; then
        # Split the line into key and value
        key=$(echo "$line" | cut -d '=' -f1)
        value=$(echo "$line" | cut -d '=' -f2-)
        # Export the variable
        export "$key=$value"
    fi
done < <(grep -v '^#' "$ENV_FILE")

# Export AUTH_SERVICE_IP
export AUTH_SERVICE_IP=auth-service  # Changed from localhost
export AUTH_SERVICE_PORT=3000

# Run docker-compose once with all environment variables set
docker compose up --build
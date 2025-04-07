#!/bin/bash

# Exit on error
set -e

# Load environment variables from .env file if it exists
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Check for required environment variables
if [ -z "$OPENAI_API_KEY" ]; then
  echo "Error: OPENAI_API_KEY is not set. Please set it in .env file or environment."
  exit 1
fi

if [ -z "$GATEKEEPER_SIGNATURE_SECRET" ]; then
  echo "Error: GATEKEEPER_SIGNATURE_SECRET is not set. Please set it in .env file or environment."
  exit 1
fi

# Start the application
echo "Starting Gatekeeper service..."
uvicorn app:app --host 0.0.0.0 --port 8000 --reload 

#!/bin/bash

# Exit on error
set -e

# Load environment variables from .env file if it exists
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Make sure required environment variables are set
if [ -z "$OPENAI_API_KEY" ]; then
  echo "Warning: OPENAI_API_KEY is not set. Using mock for tests."
  export OPENAI_API_KEY="test_api_key"
fi

if [ -z "$GATEKEEPER_SIGNATURE_SECRET" ]; then
  echo "Warning: GATEKEEPER_SIGNATURE_SECRET is not set. Using mock for tests."
  export GATEKEEPER_SIGNATURE_SECRET="test_secret"
fi

# Run pytest
echo "Running tests..."
python -m pytest -xvs 

Below is a complete implementation specification for “Gatekeeper,” a Python‐based content moderation gatekeeper service using FastAPI. The service accepts image (as base64 strings) or text along with additional metadata, forwards them to the OpenAI moderation endpoint, and returns the moderation result along with a cryptographic signature that the downstream consumer can verify using a shared secret stored in an environment variable.

─────────────────────────────
Overview
─────────────────────────────

• Built with FastAPI for high-performance API endpoints.
• Uses OpenAI’s moderation API (configurable via environment variables).
• Supports both text and image (base64 encoded) inputs.
• Returns standardized moderation results plus a signature for integrity validation.
• Zero retention and stateless – no input is stored after processing.
• CORS is enabled globally.
• A Dockerfile is provided for containerized deployment.

─────────────────────────────
Architecture & Key Components
─────────────────────────────

1. API Endpoint (```POST /moderate```):
  • Accepts JSON payload with one or more content items.
  • Each item is a dict with a type (e.g., "text" or "image") and the content.
2. OpenAI Integration:
  • Uses the OpenAI Python SDK to send the input for moderation.
  • The model and other parameters (like temperature if desired) are configurable via environment variables.
3. Signature Generation:
  • After receiving the moderation result, a HMAC-SHA256 signature is computed over the JSON response payload.
  • The signature secret is stored as an environment variable (e.g. ```GATEKEEPER_SIGNATURE_SECRET```).
4. CORS Middleware:
  • Uses FastAPI’s CORSMiddleware for cross-origin requests.
5. Deployment:
  • Dockerfile builds the container and runs the service with Uvicorn.

─────────────────────────────
Endpoint Contract
─────────────────────────────

Request:
```json
{
  "input": [
    { "type": "text", "text": "Some content here" },
    { "type": "image", "base64": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg..." }
  ]
}
```
– The service accepts a list in the “input” field.
– For images, the client can send the base64 URL string either under key “base64” or send it in the same format as OpenAI expects (i.e. as a URL beginning with “data:…”).

Response:
```json
{
  "id": "modr-123456",
  "model": "omni-moderation-latest",
  "results": [ /* OpenAI moderation results */ ],
  "signature": "abcdef1234567890"
}
```

The returned ```signature``` is computed as the HMAC-SHA256 digest (hex encoded) of the JSON string of the moderation response (excluding the signature field).

─────────────────────────────
Configuration via Environment Variables
─────────────────────────────

• ```OPENAI_API_KEY``` – API key for OpenAI.
• ```GATEKEEPER_SIGNATURE_SECRET``` – Secret key used to sign responses.
• ```OPENAI_MODERATION_MODEL``` – Moderation model (default: "omni-moderation-latest").
• Additional OpenAI parameters might be added as separate settings.

─────────────────────────────
Implementation Code
─────────────────────────────

Below is the full Python implementation for the Gatekeeper service using FastAPI:

```python
import os
import json
import hmac
import hashlib
from typing import List, Union

import openai
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Load configuration from environment
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
SIGNING_SECRET = os.environ.get("GATEKEEPER_SIGNATURE_SECRET")
MODERATION_MODEL = os.environ.get("OPENAI_MODERATION_MODEL", "omni-moderation-latest")
if not OPENAI_API_KEY or not SIGNING_SECRET:
    raise EnvironmentError("Missing required environment variables.")

openai.api_key = OPENAI_API_KEY

# Pydantic models for runtime validation
class TextInput(BaseModel):
    type: str = Field(..., regex="^text$")
    text: str

class ImageInput(BaseModel):
    type: str = Field(..., regex="^(image)$")
    base64: str  # full data URL e.g., data:image/png;base64,...

ContentInput = Union[TextInput, ImageInput]

class ModerationRequest(BaseModel):
    input: List[ContentInput]

# Define FastAPI application
app = FastAPI(title="Gatekeeper Content Moderation Service")

# Enable CORS (for simplicity, allow all origins; adjust as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def compute_signature(payload: dict) -> str:
    # Exclude the signature field (if exists) and compute digest over sorted json
    payload_str = json.dumps(payload, sort_keys=True)
    signature = hmac.new(
        SIGNING_SECRET.encode("utf-8"), payload_str.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return signature

def prepare_input(inputs: List[ContentInput]) -> List[dict]:
    prepared = []
    for item in inputs:
        if item.type == "text":
            prepared.append({"type": "text", "text": item.text})
        elif item.type == "image":
            # Map image to the OpenAI API expected 'image_url' field with base64 data.
            prepared.append({"type": "image_url", "image_url": {"url": item.base64}})
        else:
            raise ValueError("Unsupported content type")
    return prepared

@app.post("/moderate")
async def moderate_content(request: ModerationRequest):
    try:
        moderation_input = prepare_input(request.input)
        # Call OpenAI moderation API
        response = openai.Moderation.create(
            model=MODERATION_MODEL,
            input=moderation_input
        )
        # Convert response to dict (if not already)
        response_dict = response.to_dict() if hasattr(response, "to_dict") else response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Compute signature and attach it to the response
    signed_response = response_dict.copy()
    signed_response["signature"] = compute_signature(response_dict)
    return signed_response
```

─────────────────────────────
Dockerfile
─────────────────────────────

Below is the Dockerfile that packages the application:

```dockerfile
# Use an official lightweight Python runtime as a parent image.
FROM python:3.9-slim

# Set environment variables to prevent .pyc files and enable stdout/stderr logging
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install dependencies
RUN pip install --upgrade pip && \
    pip install fastapi uvicorn openai

# Copy the application code
WORKDIR /app
COPY . /app

# Expose port 8000 and run the application with Uvicorn
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

─────────────────────────────
Testing & Validation
─────────────────────────────

• Use API clients such as curl or Postman to send a POST request to ```/moderate``` with valid JSON.
• Validate that the response contains the fields from the OpenAI moderation output plus a valid signature.
• The recipient service should re-compute the signature over the response object (excluding the signature field) to confirm integrity.

─────────────────────────────
Customization & Extensibility
─────────────────────────────

• Adjust/modulate parameters for the OpenAI moderation call via additional environment variables.
• Extend the input model (or filter) to allow alternative input formats.
• The service is stateless, so horizontal scaling (for high performance) is simplified.

─────────────────────────────
Explanation
─────────────────────────────

This specification sets up a simple yet robust moderation gatekeeper service. Each request payload is validated using Pydantic. The images are sent as base64 data strings, which are packaged into the format the OpenAI API expects. A cryptographic signature is computed (using HMAC-SHA256 with a secret from the environment) for the entire moderation output—thus enabling downstream systems to verify that the response came from a trusted source. The service is deployed inside a Docker container, ensuring an isolated and reproducible environment.

This design follows best practices for secret management (via environment variables), stateless service design (for scalability), and secure signature generation for message integrity verification.

Citations:
 OpenAI Moderation API Documentation
 FastAPI and Docker Best Practices


# Gatekeeper
Image and text moderation service powered by OpenAI's moderation API.

## Overview

Gatekeeper is a Python-based content moderation service that uses FastAPI to provide a high-performance API for moderating text and images. It forwards content to OpenAI's moderation API and returns the moderation result with a cryptographic signature for verification.

Key features:
- Built with FastAPI for high-performance API endpoints
- Uses OpenAI's moderation API
- Supports both text and image (base64 encoded) inputs
- Optional image analysis using OpenAI's vision models
- Evaluates text both individually and collectively for comprehensive moderation
- Returns standardized moderation results plus a signature for integrity validation
- Zero retention and stateless – no input is stored after processing
- Security features including rate limiting, API key authentication, and input validation
- Comprehensive logging of security events
- CORS with configurable origins
- Containerized with Docker for easy deployment

## Setup

### Environment Variables

Create a `.env` file based on the `.env.example` template:

```sh
cp .env.example .env
```

Then edit the `.env` file to set your OpenAI API key, signature secret, and security parameters:

```
# Required settings
OPENAI_API_KEY=your_openai_api_key_here
GATEKEEPER_SIGNATURE_SECRET=your_signature_secret_here
OPENAI_MODERATION_MODEL=text-moderation-latest

# Vision settings
GATEKEEPER_ENABLE_VISION=false
GATEKEEPER_VISION_MODEL=gpt-4o-mini
GATEKEEPER_VISION_DETAIL=auto
GATEKEEPER_VISION_PROMPT="Analyze this image for a restaurant review or venue listing..."

# Security settings
GATEKEEPER_ALLOWED_ORIGINS=https://yourdomain.com,https://anotherdomain.com
GATEKEEPER_API_KEYS=key1,key2,key3
GATEKEEPER_MAX_TEXT_LENGTH=10000
GATEKEEPER_MAX_IMAGE_SIZE=5242880
GATEKEEPER_MAX_ITEMS=10
GATEKEEPER_RATE_LIMIT_TIMES=10
GATEKEEPER_RATE_LIMIT_SECONDS=60
```

### Installation

#### Local Development

1. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

2. Run the server:
   ```sh
   uvicorn app:app --reload
   ```

The API will be available at http://localhost:8000

#### Docker Deployment

1. Build the Docker image:
   ```sh
   docker build -t gatekeeper .
   ```

2. Run the container:
   ```sh
   docker run -p 8000:8000 --env-file .env gatekeeper
   ```

## API Usage

### Authentication

When API key authentication is enabled, include your API key in the `X-API-Key` header:

```
X-API-Key: your-api-key-here
```

### Rate Limiting

The API enforces rate limiting based on client IP address. By default, this is set to 10 requests per 60 seconds, but can be configured via environment variables. When rate limits are exceeded, the API returns a `429 Too Many Requests` response.

### Content Size Limits

The API enforces limits on:
- Maximum text length (default: 10,000 characters)
- Maximum image size (default: 5MB)
- Maximum number of items per request (default: 10)

### Moderate Content

**Endpoint**: `POST /moderate`

The API supports flexible input combinations:
- Text only: One or more text items
- Image only: One or more image items
- Mixed content: Any combination of text and images (up to the configured maximum items)

**Request Example with Multiple Items**:
```json
{
  "input": [
    { "type": "text", "text": "This restaurant has amazing food!" },
    { "type": "text", "text": "The service was excellent and I highly recommend the steak." },
    { "type": "image", "base64": "data:image/jpeg;base64,/9j/4AAQSkZ..." },
    { "type": "image", "base64": "data:image/jpeg;base64,iVBORw0KGg..." }
  ],
  "analyze_images": true
}
```

The `analyze_images` parameter is optional and defaults to `false`. If set to `true` and vision analysis is enabled in the server configuration, images will be analyzed using OpenAI's vision models after moderation.

**Response Example with Multiple Items**:
```json
{
  "id": "modr-123456",
  "model": "text-moderation-latest",
  "results": [
    {
      "flagged": false,
      "categories": {
        "hate": false,
        "harassment": false,
        "self-harm": false,
        "sexual": false,
        "violence": false
      },
      "category_scores": {
        "hate": 0.0,
        "harassment": 0.0,
        "self-harm": 0.0,
        "sexual": 0.0,
        "violence": 0.0
      }
    },
    {
      "flagged": false,
      "categories": {
        "hate": false,
        "harassment": false,
        "self-harm": false,
        "sexual": false,
        "violence": false
      },
      "category_scores": {
        "hate": 0.0,
        "harassment": 0.0,
        "self-harm": 0.0,
        "sexual": 0.0,
        "violence": 0.0
      }
    },
    {
      "flagged": false,
      "categories": {
        "hate": false,
        "harassment": false,
        "self-harm": false,
        "sexual": false,
        "violence": false
      },
      "category_scores": {
        "hate": 0.0,
        "harassment": 0.0,
        "self-harm": 0.0,
        "sexual": 0.0,
        "violence": 0.0
      }
    },
    {
      "flagged": false,
      "categories": {
        "hate": false,
        "harassment": false,
        "self-harm": false,
        "sexual": false,
        "violence": false
      },
      "category_scores": {
        "hate": 0.0,
        "harassment": 0.0,
        "self-harm": 0.0,
        "sexual": 0.0,
        "violence": 0.0
      }
    }
  ],
  "combined_text_moderation": {
    "flagged": false,
    "categories": {
      "hate": false,
      "harassment": false,
      "self-harm": false,
      "sexual": false,
      "violence": false
    },
    "category_scores": {
      "hate": 0.0,
      "harassment": 0.0,
      "self-harm": 0.0,
      "sexual": 0.0,
      "violence": 0.0
    }
  },
  "vision_analysis": [
    {
      "image_index": 2,
      "analysis": "This image shows a plate of beautifully presented food in what appears to be a restaurant setting. The dish looks like a well-plated steak with garnishes and side dishes. The lighting is good, the food appears appetizing, and the image is of high quality. This is perfectly appropriate for a restaurant listing or review as it showcases the food offerings. VERDICT: APPROPRIATE",
      "flagged": false
    },
    {
      "image_index": 3,
      "analysis": "This image shows the interior of a restaurant with tables and chairs. The space appears clean, well-lit, and professionally designed. This is an appropriate image for a restaurant listing as it accurately represents the dining environment for potential customers. There are no inappropriate elements or overlays in the image. VERDICT: APPROPRIATE",
      "flagged": false
    }
  ],
  "flagged": false,
  "signature": "abcdef1234567890"
}
```

**Response Fields**:

- `flagged`: Top-level boolean indicating if any content (individual texts, combined text, or images) was flagged as inappropriate
- `results`: OpenAI moderation results for each individual input item
- `combined_text_moderation`: Moderation result from evaluating all text items together as a single input (only relevant when multiple text items are present)
- `vision_analysis`: (Only if requested) Analysis of images, including:
  - `image_index`: The index of the image in the input array
  - `analysis`: The text analysis of the image content
  - `flagged`: Boolean indicating if the image was flagged as inappropriate
- `signature`: HMAC-SHA256 signature of the response for verification

### Text Evaluation Approach

The service uses a comprehensive approach for text moderation:

1. **Individual Evaluation**: Each text item is evaluated separately for inappropriate content.
2. **Collective Evaluation**: All text items are combined and evaluated as a whole to catch issues that might only be apparent when text fragments are considered together.

This dual-layered approach helps identify complex issues such as:
- Content that becomes problematic only when considered as a whole
- Instructions or messages that individually seem innocuous but collectively form harmful content
- Context-dependent issues where meaning changes when multiple messages are combined

The `combined_text_moderation` field only contains meaningful data when there are multiple text items in the request. For single text items or requests with no text, this field will exist but won't provide additional insights beyond the individual item moderation.

### Image Analysis Configuration

The image analysis feature can be configured with these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| GATEKEEPER_ENABLE_VISION | Enable/disable vision analysis | false |
| GATEKEEPER_VISION_MODEL | OpenAI model to use for vision | gpt-4o-mini |
| GATEKEEPER_VISION_DETAIL | Detail level for image analysis (low/high/auto) | auto |
| GATEKEEPER_VISION_PROMPT | Custom prompt for image analysis | "Analyze this image for a restaurant review..." |

### Moderation Threshold Configuration

Gatekeeper allows you to set custom thresholds for each content category to override OpenAI's default flagging behavior. By default, OpenAI only flags content when it's highly confident the content violates their policies. You can adjust these thresholds to be more or less sensitive depending on your needs.

Set these thresholds using environment variables with the pattern `GATEKEEPER_THRESHOLD_<CATEGORY>` where `<CATEGORY>` is the uppercase name of the category (e.g., HARASSMENT, HATE, SEXUAL, etc.).

Examples:
```
GATEKEEPER_THRESHOLD_HARASSMENT=0.1
GATEKEEPER_THRESHOLD_HATE=0.1
GATEKEEPER_THRESHOLD_SEXUAL=0.3
GATEKEEPER_THRESHOLD_VIOLENCE=0.2
```

For convenience, you can also set a global threshold that applies to all categories using:
```
GATEKEEPER_THRESHOLD_ALL=0.2
```

When using `GATEKEEPER_THRESHOLD_ALL`, this threshold will be applied to any category that doesn't have a specific threshold set. Category-specific thresholds will always take precedence over the global threshold.

The threshold values range from 0.0 to 1.0:
- A value of 0.0 would flag all content in that category
- A value of 1.0 would only flag content if OpenAI is 100% confident it violates the policy
- Default thresholds if not specified: harassment=0.1, hate=0.1

When a category score from OpenAI exceeds your specified threshold, Gatekeeper will flag the content even if OpenAI's default classification did not flag it. This allows for fine-tuning the sensitivity of moderation based on your specific requirements.

### Error Handling

The API returns appropriate HTTP status codes for different error scenarios:
- `400 Bad Request`: Invalid request format
- `403 Forbidden`: Invalid or missing API key
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side errors

Error responses have a consistent format:
```json
{
  "detail": "Error message"
}
```

### Security Logging

The service logs security events to both the console and a `security.log` file. Log entries include:
- API key validation failures
- Rate limit violations
- Malformed requests
- Service errors
- Request processing information (without content details)

### Verifying Signatures

To verify that a response came from the Gatekeeper service, recompute the signature:

```python
import hmac
import hashlib
import json

def verify_signature(response, secret):
    # Create a copy of the response without the signature
    payload = response.copy()
    received_signature = payload.pop("signature", None)
    
    # Compute the signature
    payload_str = json.dumps(payload, sort_keys=True)
    expected_signature = hmac.new(
        secret.encode("utf-8"), 
        payload_str.encode("utf-8"), 
        hashlib.sha256
    ).hexdigest()
    
    # Compare signatures
    return hmac.compare_digest(expected_signature, received_signature)
```

## Documentation

API documentation is available at http://localhost:8000/docs when the server is running.

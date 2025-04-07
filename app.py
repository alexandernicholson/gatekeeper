import os
import json
import hmac
import hashlib
import time
import logging
import base64
from typing import List, Dict, Any, Optional

from openai import OpenAI
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, validator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("security.log")
    ]
)
security_logger = logging.getLogger("gatekeeper.security")

# Load configuration from environment
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
SIGNING_SECRET = os.environ.get("GATEKEEPER_SIGNATURE_SECRET")
MODERATION_MODEL = os.environ.get("OPENAI_MODERATION_MODEL", "text-moderation-latest")
VISION_MODEL = os.environ.get("GATEKEEPER_VISION_MODEL", "gpt-4o-mini")
ALLOWED_ORIGINS = os.environ.get("GATEKEEPER_ALLOWED_ORIGINS", "").split(",")
API_KEYS = os.environ.get("GATEKEEPER_API_KEYS", "").split(",")

# Vision settings
ENABLE_VISION = os.environ.get("GATEKEEPER_ENABLE_VISION", "false").lower() in ("true", "1", "t")
VISION_PROMPT = os.environ.get(
    "GATEKEEPER_VISION_PROMPT", 
    "Analyze this image for a restaurant review or venue listing. "
    "Describe the content and identify anything inappropriate or irrelevant for a dining venue. "
    "Check for: non-food/restaurant content, offensive material, graphics/text overlays, "
    "or poor quality. Determine if this image is suitable for a restaurant listing or review. "
    "Respond with a JSON object following this exact format: "
    "{ \"analysis\": \"your detailed analysis here\", "
    "\"is_suitable\": boolean indicating if the image is suitable for a restaurant listing (true/false) }. "
    "The response must be valid JSON."
)
VISION_DETAIL = os.environ.get("GATEKEEPER_VISION_DETAIL", "auto")
if VISION_DETAIL not in ["low", "high", "auto"]:
    VISION_DETAIL = "auto"

# Remove empty strings from lists
ALLOWED_ORIGINS = [origin for origin in ALLOWED_ORIGINS if origin]
API_KEYS = [key for key in API_KEYS if key]

# Security limits
MAX_TEXT_LENGTH = int(os.environ.get("GATEKEEPER_MAX_TEXT_LENGTH", "10000"))
MAX_IMAGE_SIZE = int(os.environ.get("GATEKEEPER_MAX_IMAGE_SIZE", "5242880"))  # 5MB
MAX_ITEMS_PER_REQUEST = int(os.environ.get("GATEKEEPER_MAX_ITEMS", "10"))
RATE_LIMIT_TIMES = int(os.environ.get("GATEKEEPER_RATE_LIMIT_TIMES", "10"))
RATE_LIMIT_SECONDS = int(os.environ.get("GATEKEEPER_RATE_LIMIT_SECONDS", "60"))

# Moderation thresholds
# Get all available thresholds with pattern GATEKEEPER_THRESHOLD_CATEGORY
MODERATION_THRESHOLDS = {}

# First check if there's a global threshold for all categories
global_threshold = None
if "GATEKEEPER_THRESHOLD_ALL" in os.environ:
    try:
        global_threshold = float(os.environ["GATEKEEPER_THRESHOLD_ALL"])
        security_logger.info(f"Loaded global moderation threshold for all categories: {global_threshold}")
    except ValueError:
        security_logger.warning(f"Invalid global threshold value for GATEKEEPER_THRESHOLD_ALL: {os.environ['GATEKEEPER_THRESHOLD_ALL']} (must be a float)")

# Then load category-specific thresholds (these will override the global threshold)
for key, value in os.environ.items():
    if key.startswith("GATEKEEPER_THRESHOLD_") and key != "GATEKEEPER_THRESHOLD_ALL":
        category = key[len("GATEKEEPER_THRESHOLD_"):].lower()
        try:
            threshold = float(value)
            MODERATION_THRESHOLDS[category] = threshold
            security_logger.info(f"Loaded custom moderation threshold: {category}={threshold}")
        except ValueError:
            security_logger.warning(f"Invalid threshold value for {key}: {value} (must be a float)")

# Initialize OpenAI client if API key is available
client = None
if OPENAI_API_KEY:
    client = OpenAI(api_key=OPENAI_API_KEY)
else:
    security_logger.warning("OPENAI_API_KEY not found in environment variables")

if not SIGNING_SECRET:
    security_logger.warning("GATEKEEPER_SIGNATURE_SECRET not found in environment variables")

# Rate limiting implementation
class RateLimiter:
    def __init__(self, times: int, seconds: int):
        self.times = times  # Number of allowed requests
        self.seconds = seconds  # Time window in seconds
        self.requests = {}  # Dictionary to store client requests
    
    async def __call__(self, request: Request):
        client_ip = request.client.host
        current_time = time.time()
        
        # Clean old requests
        self.requests = {
            ip: [request_time for request_time in request_times if current_time - request_time < self.seconds] 
            for ip, request_times in self.requests.items()
        }
        
        # Check current client
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        # Too many requests
        if len(self.requests[client_ip]) >= self.times:
            security_logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests, please try again later"
            )
        
        # Add current request
        self.requests[client_ip].append(current_time)
        return True

# API key validation
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def validate_api_key(api_key: Optional[str] = Depends(api_key_header), request: Request = None):
    # Skip validation if no API keys defined
    if not API_KEYS:
        return True
        
    if not api_key or api_key not in API_KEYS:
        client_ip = request.client.host if request else "unknown"
        security_logger.warning(f"Invalid or missing API key from IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key"
        )
    return True

# Pydantic models for runtime validation
class TextInput(BaseModel):
    type: str = Field(..., pattern="^text$")
    text: str
    
    @validator('text')
    def validate_text_length(cls, v):
        if len(v) > MAX_TEXT_LENGTH:
            raise ValueError(f"Text exceeds maximum length of {MAX_TEXT_LENGTH} characters")
        return v

class ImageInput(BaseModel):
    type: str = Field(..., pattern="^image$")
    base64: str  # full data URL e.g., data:image/png;base64,...
    
    @validator('base64')
    def validate_image_size(cls, v):
        # Calculate estimated decoded size
        data_part = v
        if v.startswith('data:'):
            # Strip metadata for size calculation
            parts = v.split(',', 1)
            if len(parts) < 2:
                raise ValueError("Invalid base64 data URL format")
            data_part = parts[1]
            
        try:
            # Check validity of base64
            base64.b64decode(data_part)
        except Exception:
            raise ValueError("Invalid base64 encoding")
            
        # Estimate decoded size (base64 is ~33% larger than binary)
        estimated_size = len(data_part) * 3 / 4
        if estimated_size > MAX_IMAGE_SIZE:
            raise ValueError(f"Image exceeds maximum size of {MAX_IMAGE_SIZE} bytes")
        return v

class ContentInput(BaseModel):
    type: str
    text: Optional[str] = None
    base64: Optional[str] = None
    
    @validator('text')
    def validate_text(cls, v, values):
        if v is not None and values.get('type') == 'text':
            if len(v) > MAX_TEXT_LENGTH:
                raise ValueError(f"Text exceeds maximum length of {MAX_TEXT_LENGTH} characters")
        return v
        
    @validator('base64')
    def validate_base64(cls, v, values):
        if v is not None and values.get('type') == 'image':
            data_part = v
            if v.startswith('data:'):
                # Strip metadata for size calculation
                parts = v.split(',', 1)
                if len(parts) < 2:
                    raise ValueError("Invalid base64 data URL format")
                data_part = parts[1]
                
            try:
                # Check validity of base64
                base64.b64decode(data_part)
            except Exception:
                raise ValueError("Invalid base64 encoding")
                
            # Estimate decoded size (base64 is ~33% larger than binary)
            estimated_size = len(data_part) * 3 / 4
            if estimated_size > MAX_IMAGE_SIZE:
                raise ValueError(f"Image exceeds maximum size of {MAX_IMAGE_SIZE} bytes")
        return v

class ModerationRequest(BaseModel):
    input: List[ContentInput]
    analyze_images: Optional[bool] = False
    
    @validator('input')
    def validate_input_count(cls, v):
        if len(v) > MAX_ITEMS_PER_REQUEST:
            raise ValueError(f"Request exceeds maximum of {MAX_ITEMS_PER_REQUEST} items")
        if len(v) == 0:
            raise ValueError("At least one input item is required")
        return v

class VisionAnalysisResult(BaseModel):
    image_index: int
    analysis: str
    flagged: bool

# Define FastAPI application
app = FastAPI(title="Gatekeeper Content Moderation Service")

# Configure global exception handler
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Always log the exception with details
    client_ip = request.client.host
    security_logger.error(f"Error processing request from {client_ip}: {str(exc)}", exc_info=True)
    
    # Return sanitized error message to client
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    if isinstance(exc, HTTPException):
        status_code = exc.status_code
    
    # Sanitize error details for client
    if status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
        error_detail = "An internal server error occurred"
    elif isinstance(exc, HTTPException):
        error_detail = exc.detail
    else:
        error_detail = "An error occurred processing your request"
    
    return JSONResponse(
        status_code=status_code,
        content={"detail": error_detail}
    )

# Enable CORS with restricted origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Initialize rate limiter
rate_limiter = RateLimiter(times=RATE_LIMIT_TIMES, seconds=RATE_LIMIT_SECONDS)

def compute_signature(payload: dict) -> str:
    """
    Compute HMAC-SHA256 signature over the payload
    """
    # Skip if no secret is available
    if not SIGNING_SECRET:
        security_logger.warning("No signature secret provided for signature computation")
        return "no_signature_secret_provided"
        
    # Exclude the signature field (if exists) and compute digest over sorted json
    payload_copy = payload.copy()
    if "signature" in payload_copy:
        del payload_copy["signature"]
        
    payload_str = json.dumps(payload_copy, sort_keys=True)
    signature = hmac.new(
        SIGNING_SECRET.encode("utf-8"), payload_str.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return signature

def prepare_input(inputs: List[ContentInput]) -> List[str]:
    """
    Prepare the input for the OpenAI moderation API
    Extracts text content only as the moderation API only accepts strings
    """
    prepared = []
    for item in inputs:
        if item.type == "text" and item.text:
            prepared.append(item.text)
        elif item.type == "image" and item.base64:
            # Skip images for moderation as they're not supported by the moderation API
            pass
        else:
            raise ValueError(f"Unsupported content type or missing required fields: {item}")
    return prepared

async def analyze_image_with_vision(image_url: str, prompt: str = VISION_PROMPT, detail: str = VISION_DETAIL) -> Dict[str, Any]:
    """
    Analyze an image using OpenAI's vision capabilities with structured output via the Responses API.
    
    Returns:
        Dict with analysis text and whether the image is flagged as inappropriate
    """
    if not OPENAI_API_KEY:
        security_logger.error("OpenAI API key is required for vision analysis")
        raise ValueError("OpenAI API key is required for vision analysis")
    
    if not client:
         security_logger.error("OpenAI client not initialized, cannot perform vision analysis.")
         raise ValueError("OpenAI client not initialized")

    # Define the desired JSON schema for the response
    vision_schema = {
        "type": "object",
        "properties": {
            "analysis": {
                "type": "string",
                "description": "Detailed analysis of the image content, checking for appropriateness and relevance to a restaurant listing or review."
            },
            "is_suitable": {
                "type": "boolean",
                "description": "Boolean indicating if the image is suitable for a restaurant listing (true) or not (false)."
            }
        },
        "required": ["analysis", "is_suitable"],
        "additionalProperties": False
    }

    try:
        # Use the Responses API with structured output (json_schema)
        response = client.responses.create(
            model=VISION_MODEL,
            input=[ # Renamed from 'messages'
                {
                    "role": "system",
                    "content": "You are an image analyst. Analyze the provided image based on the user's prompt and respond strictly in the specified JSON format."
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": prompt},
                        {
                            "type": "input_image",
                            "image_url": image_url
                        }
                    ]
                }
            ],
            text={ # Added 'text' parameter for structured output
                "format": {
                    "type": "json_schema",
                    "name": "vision_analysis_result",
                    "schema": vision_schema,
                    "strict": True # Enforce schema adherence
                }
            }
        )

        # Handle potential errors or refusals based on response status
        if response.status != "completed":
            error_reason = response.incomplete_details.reason if response.incomplete_details else "unknown reason"
            security_logger.error(f"Vision analysis incomplete: {response.status}, reason: {error_reason}")
            # Return a default non-flagged response in case of incomplete analysis
            return {
                "analysis": f"Analysis failed: Incomplete response from model ({error_reason})",
                "flagged": False 
            }

        # Check for refusal in the output content
        if response.output and response.output[0].content and response.output[0].content[0].type == "refusal":
             refusal_message = response.output[0].content[0].refusal
             security_logger.warning(f"Vision analysis refused by model: {refusal_message}")
             return {
                "analysis": f"Analysis failed: Model refused request - {refusal_message}",
                "flagged": False 
             }

        # Extract the analysis from the response output_text
        if response.output_text:
            try:
                # Parse and log JSON response from output_text
                security_logger.info(f"Vision model response text: {response.output_text}")
                result = json.loads(response.output_text)
                
                # Get the analysis text and verdict
                analysis_text = result.get("analysis", "Analysis missing in response.")
                is_suitable = result.get("is_suitable", False) # Default to not suitable if key missing
                
                # Flag if not suitable
                flagged = not is_suitable
                
                return {
                    "analysis": analysis_text,
                    "flagged": flagged
                }
            except json.JSONDecodeError as e:
                # Fallback if not valid JSON (should be less likely with strict schema)
                security_logger.error(f"Invalid JSON from vision model despite schema: {e}. Response text: {response.output_text}")
                analysis_text = response.output_text # Return raw text if parsing fails
                # Try a simple check in the raw text as a last resort
                flagged = "not suitable" in analysis_text.lower() or "inappropriate" in analysis_text.lower()
                return {
                    "analysis": analysis_text,
                    "flagged": flagged
                }
        else:
            security_logger.error("Vision analysis failed: No output_text from vision model.")
            return {
                "analysis": "Analysis failed: No output text from vision model.",
                "flagged": False
            }
        
    except Exception as e:
        security_logger.error(f"Error during vision analysis API call: {str(e)}", exc_info=True)
        return {
            "analysis": f"Analysis failed due to exception: {str(e)}",
            "flagged": False  # Conservative approach - if analysis fails, don't flag
        }

@app.get("/")
async def root():
    """
    Root endpoint for health check
    """
    return {"status": "ok", "message": "Gatekeeper service is running"}

@app.post("/moderate")
async def moderate_content(
    request: ModerationRequest,
    _: bool = Depends(rate_limiter),
    __: bool = Depends(validate_api_key),
    http_request: Request = None
):
    """
    Endpoint to moderate content using OpenAI's moderation API
    """
    client_ip = http_request.client.host if http_request else "unknown"
    
    if not client:
        security_logger.error(f"Moderation attempt from {client_ip} failed: OpenAI API key not configured")
        raise HTTPException(status_code=500, detail="Service configuration error")
    
    try:
        # Log moderation request (without the actual content for privacy)
        security_logger.info(f"Processing moderation request from {client_ip} with {len(request.input)} items")
        
        # Extract text items for moderation
        text_items = prepare_input(request.input)
        
        # Initialize response with default values
        response_dict = {
            "results": [],
            "combined_text_moderation": {
                "flagged": False,
                "categories": {},
                "category_scores": {}
            }
        }
        
        # Only call moderation API if there are text items
        any_content_flagged = False
        if text_items:
            # Call OpenAI moderation API for individual items
            response = client.moderations.create(
                model=MODERATION_MODEL,
                input=text_items
            )
            
            # Convert response to dict
            response_dict = response.model_dump() if hasattr(response, "model_dump") else response
            
            # Apply custom thresholds to individual results
            if "results" in response_dict:
                for i, result in enumerate(response_dict["results"]):
                    original_flagged = result.get("flagged", False)
                    
                    # Check categories against custom thresholds
                    for category, threshold in MODERATION_THRESHOLDS.items():
                        score = result.get("category_scores", {}).get(category, 0)
                        if score >= threshold:
                            # Log that we're overriding the default flagging
                            security_logger.info(f"Custom threshold triggered: {category}={score} exceeds threshold {threshold}")
                            # Set the category to flagged
                            result["categories"][category] = True
                            # Set the overall result to flagged
                            result["flagged"] = True
                    
                    # Also check with global threshold for categories without specific thresholds
                    if global_threshold is not None:
                        for category, score in result.get("category_scores", {}).items():
                            # Skip categories that already have a specific threshold
                            if category in MODERATION_THRESHOLDS:
                                continue
                            
                            # Skip None or non-numeric scores
                            if score is None:
                                continue
                                
                            if score >= global_threshold:
                                security_logger.info(f"Global threshold triggered: {category}={score} exceeds global threshold {global_threshold}")
                                # Set the category to flagged
                                result["categories"][category] = True
                                # Set the overall result to flagged
                                result["flagged"] = True
                    
                    # Check if any content was flagged after custom threshold check
                    if result.get("flagged", False):
                        any_content_flagged = True
                    
                    security_logger.info(f"Moderation result for item {i}: original_flagged={original_flagged}, after_custom_check={result.get('flagged', False)}")
        
        # Perform combined text moderation
        combined_text_flagged = False
        # Only perform combined evaluation if there's more than one text item
        if len(text_items) > 1:
            try:
                combined_text = " ".join(text_items)
                combined_response = client.moderations.create(
                    model=MODERATION_MODEL,
                    input=[combined_text]
                )
                
                combined_response_dict = combined_response.model_dump() if hasattr(combined_response, "model_dump") else combined_response
                
                # Add combined text moderation results to response
                if combined_response_dict.get("results"):
                    combined_result = combined_response_dict.get("results", [{}])[0]
                    response_dict["combined_text_moderation"] = combined_result
                    
                    # Apply custom thresholds to combined result
                    original_flagged = combined_result.get("flagged", False)
                    
                    for category, threshold in MODERATION_THRESHOLDS.items():
                        score = combined_result.get("category_scores", {}).get(category, 0)
                        if score >= threshold:
                            # Log that we're overriding the default flagging
                            security_logger.info(f"Custom threshold triggered for combined text: {category}={score} exceeds threshold {threshold}")
                            # Set the category to flagged
                            combined_result["categories"][category] = True
                            # Set the overall result to flagged
                            combined_result["flagged"] = True
                    
                    # Also check with global threshold for categories without specific thresholds
                    if global_threshold is not None:
                        for category, score in combined_result.get("category_scores", {}).items():
                            # Skip categories that already have a specific threshold
                            if category in MODERATION_THRESHOLDS:
                                continue
                            
                            # Skip None or non-numeric scores
                            if score is None:
                                continue
                                
                            if score >= global_threshold:
                                security_logger.info(f"Global threshold triggered for combined text: {category}={score} exceeds global threshold {global_threshold}")
                                # Set the category to flagged
                                combined_result["categories"][category] = True
                                # Set the overall result to flagged
                                combined_result["flagged"] = True
                    
                    # Check if combined text was flagged after custom threshold check
                    if combined_result.get("flagged", False):
                        combined_text_flagged = True
                        
                    security_logger.info(f"Combined moderation result: original_flagged={original_flagged}, after_custom_check={combined_result.get('flagged', False)}")
                    
            except Exception as e:
                security_logger.error(f"Error performing combined text moderation: {str(e)}")
                # Add empty combined moderation result if it fails
                response_dict["combined_text_moderation"] = {
                    "flagged": False,
                    "categories": {},
                    "category_scores": {}
                }
        else:
            # If there's only one or zero text items, no need for combined moderation
            response_dict["combined_text_moderation"] = {
                "flagged": False,
                "categories": {},
                "category_scores": {}
            }
        
        # Analyze images if requested and enabled globally
        vision_results = []
        vision_flagged = False
        if request.analyze_images and ENABLE_VISION:
            security_logger.info(f"Analyzing images with vision for request from {client_ip}")
            
            # Find all images in the input
            for i, item in enumerate(request.input):
                if item.type == "image" and item.base64:
                    try:
                        # Analyze image with vision model
                        image_url = item.base64
                        if not image_url.startswith("data:"):
                            image_url = f"data:image/png;base64,{image_url}"
                            
                        vision_result = await analyze_image_with_vision(image_url)
                        result_obj = {
                            "image_index": i,
                            "analysis": vision_result["analysis"],
                            "flagged": vision_result["flagged"]
                        }
                        
                        if vision_result["flagged"]:
                            vision_flagged = True
                            
                        vision_results.append(result_obj)
                    except Exception as e:
                        security_logger.error(f"Error analyzing image {i} from {client_ip}: {str(e)}")
                        vision_results.append({
                            "image_index": i,
                            "analysis": f"Analysis failed: {str(e)}",
                            "flagged": False
                        })
            
            # Add vision results to the response
            response_dict["vision_analysis"] = vision_results
        
        # Add top-level flagged field (true if any content or image was flagged)
        response_dict["flagged"] = any_content_flagged or combined_text_flagged or vision_flagged
        
        # Compute signature and attach it to the response
        signed_response = response_dict.copy()
        signed_response["signature"] = compute_signature(response_dict)
        
        # Log successful moderation (without content details)
        security_logger.info(f"Successfully processed moderation request from {client_ip}")
        
        return signed_response
        
    except Exception as e:
        # Log the error (but don't expose details to client)
        security_logger.error(f"Error processing moderation request from {client_ip}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred processing your request"
        )

if __name__ == "__main__":
    import uvicorn
    security_logger.info("Starting Gatekeeper service")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True) 

from fastapi.testclient import TestClient
import os
import json
import hmac
import hashlib
import pytest
from unittest.mock import patch, MagicMock

from app import app, compute_signature

# Create test client
client = TestClient(app)

# Mock environment variables for testing
os.environ["GATEKEEPER_SIGNATURE_SECRET"] = "test_secret"
os.environ["OPENAI_API_KEY"] = "test_api_key"
os.environ["GATEKEEPER_API_KEYS"] = "test_api_key_1,test_api_key_2"
os.environ["GATEKEEPER_ALLOWED_ORIGINS"] = "https://test.com"
os.environ["GATEKEEPER_MAX_TEXT_LENGTH"] = "1000"
os.environ["GATEKEEPER_MAX_IMAGE_SIZE"] = "1048576"  # 1MB
os.environ["GATEKEEPER_MAX_ITEMS"] = "5"
os.environ["GATEKEEPER_RATE_LIMIT_TIMES"] = "20"  # Higher for testing
os.environ["GATEKEEPER_RATE_LIMIT_SECONDS"] = "60"
os.environ["GATEKEEPER_ENABLE_VISION"] = "true"  # Enable vision for testing
os.environ["GATEKEEPER_VISION_MODEL"] = "gpt-4o-mini"
os.environ["GATEKEEPER_VISION_DETAIL"] = "auto"

# Valid test API key from the mock environment
TEST_API_KEY = "test_api_key_1"


def test_root_endpoint():
    """Test the root endpoint for health check"""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "message": "Gatekeeper service is running"}


@patch("openai.Moderation.create")
def test_moderate_text_endpoint_with_auth(mock_moderation):
    """Test the /moderate endpoint with text input and valid API key"""
    # Mock OpenAI response
    mock_response = MagicMock()
    mock_response.to_dict.return_value = {
        "id": "modr-123456",
        "model": "text-moderation-latest",
        "results": [
            {
                "flagged": False,
                "categories": {
                    "hate": False,
                    "harassment": False,
                    "self-harm": False,
                    "sexual": False,
                    "violence": False,
                },
                "category_scores": {
                    "hate": 0.0,
                    "harassment": 0.0,
                    "self-harm": 0.0,
                    "sexual": 0.0,
                    "violence": 0.0,
                },
            }
        ],
    }
    mock_moderation.return_value = mock_response

    # Test payload
    payload = {
        "input": [
            {"type": "text", "text": "This is a test message"}
        ]
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 200
    response_data = response.json()
    
    # Check basic structure
    assert "id" in response_data
    assert "model" in response_data
    assert "results" in response_data
    assert "signature" in response_data
    
    # Verify signature
    expected_payload = response_data.copy()
    del expected_payload["signature"]
    expected_signature = compute_signature(expected_payload)
    assert response_data["signature"] == expected_signature


@patch("openai.Moderation.create")
def test_moderate_text_endpoint_without_auth(mock_moderation):
    """Test the /moderate endpoint without API key should fail"""
    # Test payload
    payload = {
        "input": [
            {"type": "text", "text": "This is a test message"}
        ]
    }

    # Make request without API key
    response = client.post("/moderate", json=payload)
    
    # Verify response
    assert response.status_code == 403  # Forbidden
    assert "detail" in response.json()


@patch("openai.Moderation.create")
@patch("app.analyze_image_with_vision")
def test_moderate_image_endpoint_with_analysis(mock_vision, mock_moderation):
    """Test the /moderate endpoint with image input and analysis"""
    # Mock OpenAI moderation response
    mock_moderation_response = MagicMock()
    mock_moderation_response.to_dict.return_value = {
        "id": "modr-123456",
        "model": "text-moderation-latest",
        "results": [
            {
                "flagged": False,
                "categories": {
                    "hate": False,
                    "harassment": False,
                    "self-harm": False,
                    "sexual": False,
                    "violence": False,
                },
                "category_scores": {
                    "hate": 0.0,
                    "harassment": 0.0,
                    "self-harm": 0.0,
                    "sexual": 0.0,
                    "violence": 0.0,
                },
            }
        ],
    }
    mock_moderation.return_value = mock_moderation_response
    
    # Mock vision analysis response
    mock_vision.return_value = {
        "analysis": "This is a high-quality image of a restaurant interior. The image shows well-arranged tables and chairs in a well-lit dining area. The decor appears modern and clean. This image is appropriate for a restaurant listing as it accurately represents the dining environment. VERDICT: APPROPRIATE",
        "flagged": False
    }

    # Test payload with image (small base64 string for testing) and analyze_images=true
    payload = {
        "input": [
            {"type": "image", "base64": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}
        ],
        "analyze_images": True
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 200
    response_data = response.json()
    
    # Check basic structure
    assert "id" in response_data
    assert "model" in response_data
    assert "results" in response_data
    assert "vision_analysis" in response_data
    assert "signature" in response_data
    
    # Check vision analysis structure
    assert len(response_data["vision_analysis"]) == 1
    assert "image_index" in response_data["vision_analysis"][0]
    assert "analysis" in response_data["vision_analysis"][0]
    assert "flagged" in response_data["vision_analysis"][0]
    assert response_data["vision_analysis"][0]["analysis"] == mock_vision.return_value["analysis"]
    assert response_data["vision_analysis"][0]["flagged"] == mock_vision.return_value["flagged"]
    
    # Check top-level flagged field
    assert "flagged" in response_data
    assert response_data["flagged"] == False  # Not flagged in this test case


@patch("openai.Moderation.create")
@patch("app.analyze_image_with_vision")
def test_moderate_image_without_analysis(mock_vision, mock_moderation):
    """Test the /moderate endpoint with image input but no analysis requested"""
    # Mock OpenAI moderation response
    mock_moderation_response = MagicMock()
    mock_moderation_response.to_dict.return_value = {
        "id": "modr-123456",
        "model": "text-moderation-latest",
        "results": [
            {
                "flagged": False,
                "categories": {
                    "hate": False,
                    "harassment": False,
                    "self-harm": False,
                    "sexual": False,
                    "violence": False,
                },
                "category_scores": {
                    "hate": 0.0,
                    "harassment": 0.0,
                    "self-harm": 0.0,
                    "sexual": 0.0,
                    "violence": 0.0,
                },
            }
        ],
    }
    mock_moderation.return_value = mock_moderation_response

    # Test payload with image but analyze_images=false
    payload = {
        "input": [
            {"type": "image", "base64": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}
        ],
        "analyze_images": False
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 200
    response_data = response.json()
    
    # Vision analysis should not be called or included in response
    mock_vision.assert_not_called()
    assert "vision_analysis" not in response_data


@patch("openai.Moderation.create")
@patch("app.analyze_image_with_vision")
def test_mixed_content_with_analysis(mock_vision, mock_moderation):
    """Test the /moderate endpoint with mixed text and image input and analysis"""
    # Mock OpenAI moderation response
    mock_moderation_response = MagicMock()
    mock_moderation_response.to_dict.return_value = {
        "id": "modr-123456",
        "model": "text-moderation-latest",
        "results": [
            {
                "flagged": False,
                "categories": {
                    "hate": False,
                    "harassment": False,
                    "self-harm": False,
                    "sexual": False,
                    "violence": False,
                },
                "category_scores": {
                    "hate": 0.0,
                    "harassment": 0.0,
                    "self-harm": 0.0,
                    "sexual": 0.0,
                    "violence": 0.0,
                },
            },
            {
                "flagged": False,
                "categories": {
                    "hate": False,
                    "harassment": False,
                    "self-harm": False,
                    "sexual": False,
                    "violence": False,
                },
                "category_scores": {
                    "hate": 0.0,
                    "harassment": 0.0,
                    "self-harm": 0.0,
                    "sexual": 0.0,
                    "violence": 0.0,
                },
            }
        ],
    }
    mock_moderation.return_value = mock_moderation_response
    
    # Mock vision analysis response
    mock_vision.return_value = {
        "analysis": "This image shows delicious food on a plate in a restaurant setting. The image is well-lit, focused, and shows the food presentation clearly. This is appropriate for a restaurant review or listing. VERDICT: APPROPRIATE",
        "flagged": False
    }

    # Test payload with text and image
    payload = {
        "input": [
            {"type": "text", "text": "This restaurant has amazing food"},
            {"type": "image", "base64": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}
        ],
        "analyze_images": True
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 200
    response_data = response.json()
    
    # Check that both text and image were moderated
    assert len(response_data["results"]) == 2
    
    # Check vision analysis
    assert "vision_analysis" in response_data
    assert len(response_data["vision_analysis"]) == 1
    assert response_data["vision_analysis"][0]["image_index"] == 1  # Second item (index 1) is the image
    assert "flagged" in response_data["vision_analysis"][0]
    
    # Check top-level flagged field
    assert "flagged" in response_data
    assert response_data["flagged"] == False  # Not flagged in this test case


@patch("openai.Moderation.create")
@patch("app.ENABLE_VISION", False)  # Temporarily disable vision for this test
def test_vision_disabled_globally(mock_moderation):
    """Test that vision analysis is not performed when disabled globally"""
    # Mock OpenAI moderation response
    mock_moderation_response = MagicMock()
    mock_moderation_response.to_dict.return_value = {
        "id": "modr-123456",
        "model": "text-moderation-latest",
        "results": [
            {
                "flagged": False,
                "categories": {
                    "hate": False,
                    "harassment": False,
                    "self-harm": False,
                    "sexual": False,
                    "violence": False,
                },
                "category_scores": {
                    "hate": 0.0,
                    "harassment": 0.0,
                    "self-harm": 0.0,
                    "sexual": 0.0,
                    "violence": 0.0,
                },
            }
        ],
    }
    mock_moderation.return_value = mock_moderation_response

    # Test payload requesting analysis, but it should be ignored since vision is disabled
    payload = {
        "input": [
            {"type": "image", "base64": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}
        ],
        "analyze_images": True
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 200
    response_data = response.json()
    
    # Vision analysis should not be included
    assert "vision_analysis" not in response_data


def test_text_size_limit():
    """Test validation for text that exceeds maximum length"""
    # Create text that exceeds the limit (1000 chars set in env var)
    long_text = "x" * 1200
    
    # Test payload with oversized text
    payload = {
        "input": [
            {"type": "text", "text": long_text}
        ]
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 422  # Validation error
    assert "detail" in response.json()


def test_too_many_items():
    """Test validation for too many items in a request"""
    # Create payload with more than allowed items (5 set in env var)
    payload = {
        "input": [{"type": "text", "text": f"Item {i}"} for i in range(6)]
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 422  # Validation error
    assert "detail" in response.json()


def test_error_handling():
    """Test error handling when OpenAI API key is missing"""
    # Temporarily remove API key
    with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
        # Test payload
        payload = {
            "input": [
                {"type": "text", "text": "This is a test message"}
            ]
        }

        # Make request with API key
        headers = {"X-API-Key": TEST_API_KEY}
        response = client.post("/moderate", json=payload, headers=headers)
        
        # Verify response
        assert response.status_code == 500
        assert "detail" in response.json()
        # Check that the error is sanitized and doesn't reveal implementation details
        assert response.json()["detail"] == "Service configuration error"


def test_invalid_input():
    """Test error handling for invalid input"""
    # Test payload with invalid input
    payload = {
        "input": [
            {"type": "unknown", "content": "This is a test message"}
        ]
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 422  # Validation error


@patch("openai.Moderation.create")
@patch("app.analyze_image_with_vision")
def test_flagged_content_detection(mock_vision, mock_moderation):
    """Test that flagged content is properly detected and reported"""
    # Mock OpenAI moderation response with flagged content
    mock_moderation_response = MagicMock()
    mock_moderation_response.to_dict.return_value = {
        "id": "modr-123456",
        "model": "text-moderation-latest",
        "results": [
            {
                "flagged": True,  # This text is flagged
                "categories": {
                    "hate": True,
                    "harassment": False,
                    "self-harm": False,
                    "sexual": False,
                    "violence": False,
                },
                "category_scores": {
                    "hate": 0.9,
                    "harassment": 0.1,
                    "self-harm": 0.0,
                    "sexual": 0.0,
                    "violence": 0.0,
                },
            }
        ],
    }
    mock_moderation.return_value = mock_moderation_response
    
    # Mock vision analysis response - not flagged
    mock_vision.return_value = {
        "analysis": "This is an appropriate image. VERDICT: APPROPRIATE",
        "flagged": False
    }

    # Test payload with text that should be flagged
    payload = {
        "input": [
            {"type": "text", "text": "This is inappropriate text"}
        ],
        "analyze_images": False
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 200
    response_data = response.json()
    
    # Check that the content is flagged at the top level
    assert "flagged" in response_data
    assert response_data["flagged"] == True  # Should be flagged
    
    # Check that the right category is flagged
    assert response_data["results"][0]["categories"]["hate"] == True


@patch("openai.Moderation.create")
@patch("app.analyze_image_with_vision")
def test_flagged_image_detection(mock_vision, mock_moderation):
    """Test that flagged images are properly detected and reported"""
    # Mock OpenAI moderation response - not flagged
    mock_moderation_response = MagicMock()
    mock_moderation_response.to_dict.return_value = {
        "id": "modr-123456",
        "model": "text-moderation-latest",
        "results": [
            {
                "flagged": False,
                "categories": {
                    "hate": False,
                    "harassment": False,
                    "self-harm": False,
                    "sexual": False,
                    "violence": False,
                },
                "category_scores": {
                    "hate": 0.0,
                    "harassment": 0.0,
                    "self-harm": 0.0,
                    "sexual": 0.0,
                    "violence": 0.0,
                },
            }
        ],
    }
    mock_moderation.return_value = mock_moderation_response
    
    # Mock vision analysis response - flagged
    mock_vision.return_value = {
        "analysis": "This image contains inappropriate content that is not suitable for a restaurant listing. It appears to show content unrelated to food or dining. VERDICT: INAPPROPRIATE",
        "flagged": True
    }

    # Test payload with an image that should be flagged by vision analysis
    payload = {
        "input": [
            {"type": "image", "base64": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}
        ],
        "analyze_images": True
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 200
    response_data = response.json()
    
    # Check that the image is flagged in the vision analysis
    assert "vision_analysis" in response_data
    assert response_data["vision_analysis"][0]["flagged"] == True
    
    # Check that the content is flagged at the top level 
    assert "flagged" in response_data
    assert response_data["flagged"] == True  # Should be flagged


@patch("openai.Moderation.create")
def test_combined_text_moderation_not_flagged(mock_moderation):
    """Test that multiple text items are evaluated both individually and together when not flagged"""
    # First call is for individual items, second call is for combined text
    mock_moderation.side_effect = [
        # Individual items moderation response
        MagicMock(to_dict=lambda: {
            "id": "modr-123456",
            "model": "text-moderation-latest",
            "results": [
                {
                    "flagged": False,
                    "categories": {
                        "hate": False,
                        "harassment": False,
                        "self-harm": False,
                        "sexual": False,
                        "violence": False,
                    },
                    "category_scores": {
                        "hate": 0.0,
                        "harassment": 0.0,
                        "self-harm": 0.0,
                        "sexual": 0.0,
                        "violence": 0.0,
                    },
                },
                {
                    "flagged": False,
                    "categories": {
                        "hate": False,
                        "harassment": False,
                        "self-harm": False,
                        "sexual": False,
                        "violence": False,
                    },
                    "category_scores": {
                        "hate": 0.0,
                        "harassment": 0.0,
                        "self-harm": 0.0,
                        "sexual": 0.0,
                        "violence": 0.0,
                    },
                },
            ],
        }),
        # Combined text moderation response
        MagicMock(to_dict=lambda: {
            "id": "modr-123457",
            "model": "text-moderation-latest",
            "results": [
                {
                    "flagged": False,
                    "categories": {
                        "hate": False,
                        "harassment": False,
                        "self-harm": False,
                        "sexual": False,
                        "violence": False,
                    },
                    "category_scores": {
                        "hate": 0.0,
                        "harassment": 0.0,
                        "self-harm": 0.0,
                        "sexual": 0.0,
                        "violence": 0.0,
                    },
                },
            ],
        }),
    ]

    # Test payload with two text items
    payload = {
        "input": [
            {"type": "text", "text": "First part of a normal message"},
            {"type": "text", "text": "Second part of a normal message"}
        ]
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 200
    response_data = response.json()
    
    # Check that moderation was called twice - once for individual items, once for combined
    assert mock_moderation.call_count == 2
    
    # Check that combined_text_moderation field exists
    assert "combined_text_moderation" in response_data
    assert response_data["combined_text_moderation"]["flagged"] == False
    
    # Check that the overall result is not flagged
    assert response_data["flagged"] == False


@patch("openai.Moderation.create")
def test_combined_text_moderation_flagged(mock_moderation):
    """Test that multiple text items are flagged when combined, even if individual items are fine"""
    # First call is for individual items, second call is for combined text
    mock_moderation.side_effect = [
        # Individual items moderation response - not flagged
        MagicMock(to_dict=lambda: {
            "id": "modr-123456",
            "model": "text-moderation-latest",
            "results": [
                {
                    "flagged": False,
                    "categories": {
                        "hate": False,
                        "harassment": False,
                        "self-harm": False,
                        "sexual": False,
                        "violence": False,
                    },
                    "category_scores": {
                        "hate": 0.0,
                        "harassment": 0.0,
                        "self-harm": 0.0,
                        "sexual": 0.0,
                        "violence": 0.0,
                    },
                },
                {
                    "flagged": False,
                    "categories": {
                        "hate": False,
                        "harassment": False,
                        "self-harm": False,
                        "sexual": False,
                        "violence": False,
                    },
                    "category_scores": {
                        "hate": 0.0,
                        "harassment": 0.0,
                        "self-harm": 0.0,
                        "sexual": 0.0,
                        "violence": 0.0,
                    },
                },
            ],
        }),
        # Combined text moderation response - flagged for harassment when combined
        MagicMock(to_dict=lambda: {
            "id": "modr-123457",
            "model": "text-moderation-latest",
            "results": [
                {
                    "flagged": True,
                    "categories": {
                        "hate": False,
                        "harassment": True,  # Flagged for harassment when combined
                        "self-harm": False,
                        "sexual": False,
                        "violence": False,
                    },
                    "category_scores": {
                        "hate": 0.05,
                        "harassment": 0.92,  # High score for harassment
                        "self-harm": 0.0,
                        "sexual": 0.0,
                        "violence": 0.0,
                    },
                },
            ],
        }),
    ]

    # Test payload with two text items that are innocuous individually but problematic when combined
    payload = {
        "input": [
            {"type": "text", "text": "First part of a message that seems fine individually"},
            {"type": "text", "text": "Second part that completes the problematic message"}
        ]
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 200
    response_data = response.json()
    
    # Check that moderation was called twice
    assert mock_moderation.call_count == 2
    
    # Check that combined_text_moderation field is flagged
    assert "combined_text_moderation" in response_data
    assert response_data["combined_text_moderation"]["flagged"] == True
    assert response_data["combined_text_moderation"]["categories"]["harassment"] == True
    
    # Check that the overall result is flagged, even though individual items were not
    assert response_data["flagged"] == True


@patch("openai.Moderation.create")
def test_single_text_item_no_combined_moderation(mock_moderation):
    """Test that for single text item, we don't need to perform combined moderation"""
    # Only one call should be made for individual moderation
    mock_moderation.return_value = MagicMock(to_dict=lambda: {
        "id": "modr-123456",
        "model": "text-moderation-latest",
        "results": [
            {
                "flagged": False,
                "categories": {
                    "hate": False,
                    "harassment": False,
                    "self-harm": False,
                    "sexual": False,
                    "violence": False,
                },
                "category_scores": {
                    "hate": 0.0,
                    "harassment": 0.0,
                    "self-harm": 0.0,
                    "sexual": 0.0,
                    "violence": 0.0,
                },
            }
        ],
    })

    # Test payload with a single text item
    payload = {
        "input": [
            {"type": "text", "text": "Just a single text item"}
        ]
    }

    # Make request with API key
    headers = {"X-API-Key": TEST_API_KEY}
    response = client.post("/moderate", json=payload, headers=headers)
    
    # Verify response
    assert response.status_code == 200
    response_data = response.json()
    
    # Check that moderation was called only once
    assert mock_moderation.call_count == 1
    
    # Check that combined_text_moderation field exists but is essentially empty
    assert "combined_text_moderation" in response_data
    assert response_data["combined_text_moderation"]["flagged"] == False
    assert len(response_data["combined_text_moderation"]["categories"]) == 0
    
    # Check that the overall result is not flagged
    assert response_data["flagged"] == False

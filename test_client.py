#!/usr/bin/env python3
"""
Test client for the Gatekeeper moderation service.
This script demonstrates how to call the moderation API and verify the signature.
"""

import os
import json
import hmac
import hashlib
import base64
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration
API_URL = "http://localhost:8000/moderate"
SIGNATURE_SECRET = os.environ.get("GATEKEEPER_SIGNATURE_SECRET", "your_signature_secret_here")
API_KEY = os.environ.get("GATEKEEPER_API_KEYS", "").split(",")[0]  # Use first API key if available

# Prepare headers
headers = {"Content-Type": "application/json"}
if API_KEY:
    headers["X-API-Key"] = API_KEY

def verify_signature(response_data, secret):
    """
    Verify the signature on a Gatekeeper response
    """
    # Extract signature
    received_signature = response_data.get("signature")
    if not received_signature:
        print("No signature found in response")
        return False
    
    # Create a copy and remove signature for verification
    payload = response_data.copy()
    payload.pop("signature")
    
    # Compute expected signature
    payload_str = json.dumps(payload, sort_keys=True)
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        payload_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    
    # Compare signatures
    is_valid = hmac.compare_digest(expected_signature, received_signature)
    return is_valid

def moderate_text(text):
    """
    Submit text for moderation
    """
    payload = {
        "input": [
            {"type": "text", "text": text}
        ]
    }
    
    response = requests.post(API_URL, json=payload, headers=headers)
    if response.status_code != 200:
        print(f"Error: {response.status_code} - {response.text}")
        return None
    
    return response.json()

def moderate_image(image_path, analyze=False):
    """
    Submit an image for moderation
    
    Args:
        image_path (str): Path to the image file
        analyze (bool, optional): Whether to request image analysis. Defaults to False.
    """
    # Load and encode image
    with open(image_path, "rb") as f:
        image_data = f.read()
    
    base64_data = base64.b64encode(image_data).decode("utf-8")
    image_type = image_path.split(".")[-1].lower()
    data_url = f"data:image/{image_type};base64,{base64_data}"
    
    payload = {
        "input": [
            {"type": "image", "base64": data_url}
        ],
        "analyze_images": analyze
    }
    
    response = requests.post(API_URL, json=payload, headers=headers)
    if response.status_code != 200:
        print(f"Error: {response.status_code} - {response.text}")
        return None
    
    return response.json()

def moderate_mixed_content(text, image_path, analyze=False):
    """
    Submit both text and image for moderation
    
    Args:
        text (str): Text to moderate
        image_path (str): Path to the image file
        analyze (bool, optional): Whether to request image analysis. Defaults to False.
    """
    # Load and encode image
    with open(image_path, "rb") as f:
        image_data = f.read()
    
    base64_data = base64.b64encode(image_data).decode("utf-8")
    image_type = image_path.split(".")[-1].lower()
    data_url = f"data:image/{image_type};base64,{base64_data}"
    
    payload = {
        "input": [
            {"type": "text", "text": text},
            {"type": "image", "base64": data_url}
        ],
        "analyze_images": analyze
    }
    
    response = requests.post(API_URL, json=payload, headers=headers)
    if response.status_code != 200:
        print(f"Error: {response.status_code} - {response.text}")
        return None
    
    return response.json()

def handle_rate_limiting():
    """
    Example of how to handle rate limiting with exponential backoff
    """
    import time
    from random import uniform
    
    max_retries = 5
    base_delay = 1  # Starting delay in seconds
    
    for attempt in range(max_retries):
        text = "This is a test for rate limiting"
        response = requests.post(API_URL, json={"input": [{"type": "text", "text": text}]}, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        
        if response.status_code == 429:  # Too Many Requests
            # Calculate delay with exponential backoff and jitter
            delay = base_delay * (2 ** attempt) + uniform(0, 1)
            print(f"Rate limit exceeded. Retrying in {delay:.2f} seconds...")
            time.sleep(delay)
            continue
        
        # Other error
        print(f"Error: {response.status_code} - {response.text}")
        return None
    
    print(f"Failed after {max_retries} attempts due to rate limiting")
    return None

def print_moderation_results(result):
    """
    Display moderation results in a readable format
    """
    print(f"Overall Content Flagged: {result.get('flagged', False)}")
    
    if "results" in result:
        print("\nIndividual Content Moderation Results:")
        print("----------------------------------")
        for i, res in enumerate(result["results"]):
            content_type = "Text" if i < len(result.get("input", [])) and result["input"][i].get("type") == "text" else "Image"
            print(f"Item #{i} ({content_type}):")
            print(f"  Flagged: {res.get('flagged', False)}")
            if res.get("categories"):
                print("  Categories:")
                for category, flagged in res["categories"].items():
                    if flagged:
                        print(f"    - {category}: {flagged}")
            print()
    
    if "combined_text_moderation" in result:
        combined = result["combined_text_moderation"]
        print("\nCombined Text Moderation Results:")
        print("-------------------------------")
        print(f"Flagged: {combined.get('flagged', False)}")
        if combined.get("categories"):
            print("Categories:")
            for category, flagged in combined["categories"].items():
                if flagged:
                    print(f"  - {category}: {flagged}")
        print()

def print_vision_analysis(result):
    """
    Display vision analysis results in a readable format
    """
    if "vision_analysis" not in result:
        print("No vision analysis results found in response.")
        return
    
    print("\nVision Analysis Results:")
    print("------------------------")
    for analysis in result["vision_analysis"]:
        print(f"Image #{analysis['image_index']}:")
        print(f"  Flagged: {analysis.get('flagged', False)}")
        print(f"  Analysis: {analysis['analysis']}")
        print()

def main():
    """
    Main function to demonstrate the Gatekeeper client
    """
    print("Gatekeeper Moderation Test Client")
    print("=================================")
    
    # Test text moderation
    print("\n1. Testing text moderation...")
    text = "This is a sample text to moderate. Is this harmful?"
    
    result = moderate_text(text)
    if result:
        print(f"Response ID: {result.get('id')}")
        print(f"Model: {result.get('model')}")
        print_moderation_results(result)
        
        # Verify signature
        is_valid = verify_signature(result, SIGNATURE_SECRET)
        print(f"Signature valid: {is_valid}")
    
    # Uncomment to test image moderation with analysis
    """
    print("\n2. Testing image moderation with analysis...")
    # Replace with your actual image path
    image_path = "test_image.jpg"
    
    result = moderate_image(image_path, analyze=True)
    if result:
        print(f"Response ID: {result.get('id')}")
        print(f"Model: {result.get('model')}")
        print(f"Overall Content Flagged: {result.get('flagged', False)}")
        
        # Print moderation results
        print_moderation_results(result)
        
        # Print vision analysis
        print_vision_analysis(result)
        
        # Verify signature
        is_valid = verify_signature(result, SIGNATURE_SECRET)
        print(f"Signature valid: {is_valid}")
    
    # Test mixed content moderation with analysis
    print("\n3. Testing mixed content moderation with analysis...")
    text = "Another sample text with an image"
    
    result = moderate_mixed_content(text, image_path, analyze=True)
    if result:
        print(f"Response ID: {result.get('id')}")
        print(f"Model: {result.get('model')}")
        print(f"Overall Content Flagged: {result.get('flagged', False)}")
        
        # Print detailed results
        print_moderation_results(result)
        
        # Print vision analysis
        print_vision_analysis(result)
        
        # Verify signature
        is_valid = verify_signature(result, SIGNATURE_SECRET)
        print(f"Signature valid: {is_valid}")
    """
    
    # Uncomment to test rate limiting handling
    """
    print("\n4. Testing rate limiting handling...")
    result = handle_rate_limiting()
    if result:
        print("Successfully received response after handling rate limiting")
    """

if __name__ == "__main__":
    main() 

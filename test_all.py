#!/usr/bin/env python3
"""
Test script for the Gatekeeper moderation service using all files
in the test/images and test/text directories.
"""

import os
import json
import hmac
import hashlib
import base64
import requests
from dotenv import load_dotenv
import glob

# Load environment variables from .env file
load_dotenv()

# Configuration
API_URL = "http://localhost:8001/moderate"  # Using port 8001 as set in docker-compose.yml
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

def load_image_as_base64(image_path):
    """
    Load an image file and convert it to base64 format
    """
    with open(image_path, "rb") as f:
        image_data = f.read()
    
    base64_data = base64.b64encode(image_data).decode("utf-8")
    image_type = image_path.split(".")[-1].lower()
    data_url = f"data:image/{image_type};base64,{base64_data}"
    
    return data_url

def load_text_file(text_path):
    """
    Load content from a text file
    """
    with open(text_path, "r") as f:
        return f.read()

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
    Main function to test the Gatekeeper service with all files in test directories
    """
    print("Gatekeeper Moderation Test Client - Testing All Files")
    print("====================================================")
    
    # Results tracking
    results = []
    
    # Test all text files
    print("\n===== Testing All Text Files =====")
    text_files = glob.glob("test/text/*.txt")
    
    for i, text_file in enumerate(text_files):
        print(f"\nTesting text file {i+1}/{len(text_files)}: {text_file}")
        text_content = load_text_file(text_file)
        
        # Extract expected result from filename
        filename = os.path.basename(text_file)
        expected_flagged = "_true" in filename.lower()
        expected_result = "FLAGGED" if expected_flagged else "NOT FLAGGED"
        
        payload = {
            "input": [
                {"type": "text", "text": text_content}
            ]
        }
        
        response = requests.post(API_URL, json=payload, headers=headers)
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            results.append({
                "filename": text_file,
                "type": "text",
                "expected": expected_result,
                "actual": "ERROR",
                "match": False
            })
            continue
        
        result = response.json()
        print_moderation_results(result)
        
        # Track result
        actual_flagged = result.get('flagged', False)
        actual_result = "FLAGGED" if actual_flagged else "NOT FLAGGED"
        match = (expected_flagged == actual_flagged)
        
        results.append({
            "filename": text_file,
            "type": "text",
            "expected": expected_result,
            "actual": actual_result,
            "match": match
        })
        
        # Verify signature
        is_valid = verify_signature(result, SIGNATURE_SECRET)
        print(f"Signature valid: {is_valid}")
    
    # Test all image files
    print("\n===== Testing All Image Files =====")
    image_files = glob.glob("test/images/*.*")
    
    for i, image_file in enumerate(image_files):
        print(f"\nTesting image file {i+1}/{len(image_files)}: {image_file}")
        
        # Extract expected result from filename
        filename = os.path.basename(image_file)
        expected_flagged = "_true" in filename.lower()
        expected_result = "FLAGGED" if expected_flagged else "NOT FLAGGED"
        
        base64_data = load_image_as_base64(image_file)
        
        payload = {
            "input": [
                {"type": "image", "base64": base64_data}
            ],
            "analyze_images": True
        }
        
        response = requests.post(API_URL, json=payload, headers=headers)
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            results.append({
                "filename": image_file,
                "type": "image",
                "expected": expected_result,
                "actual": "ERROR",
                "match": False
            })
            continue
        
        result = response.json()
        print(f"Overall Content Flagged: {result.get('flagged', False)}")
        
        # Track result
        actual_flagged = result.get('flagged', False)
        actual_result = "FLAGGED" if actual_flagged else "NOT FLAGGED"
        match = (expected_flagged == actual_flagged)
        
        results.append({
            "filename": image_file,
            "type": "image",
            "expected": expected_result,
            "actual": actual_result,
            "match": match
        })
        
        # Print vision analysis
        print_vision_analysis(result)
        
        # Verify signature
        is_valid = verify_signature(result, SIGNATURE_SECRET)
        print(f"Signature valid: {is_valid}")
    
    # Print results table
    print("\n===== Results Table =====")
    print(f"{'Filename':<30} {'Type':<10} {'Expected':<12} {'Actual':<12} {'Match':<5}")
    print("-" * 70)
    
    total_files = len(results)
    correct_matches = 0
    
    for item in results:
        filename = os.path.basename(item["filename"])
        print(f"{filename:<30} {item['type']:<10} {item['expected']:<12} {item['actual']:<12} {'✓' if item['match'] else '✗'}")
        if item['match']:
            correct_matches += 1
    
    # Print summary
    print("\n===== Test Summary =====")
    print(f"Total files tested: {total_files}")
    print(f"Correct predictions: {correct_matches}")
    print(f"Accuracy: {(correct_matches / total_files * 100) if total_files > 0 else 0:.2f}%")
    
    print("\nAll tests completed!")

if __name__ == "__main__":
    main() 

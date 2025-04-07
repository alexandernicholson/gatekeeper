#!/usr/bin/env python3
"""
Test script for single file analysis to extract detailed category scores.
"""

import os
import json
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration
API_URL = "http://localhost:8001/moderate"  # Using port 8001 as set in docker-compose.yml
API_KEY = os.environ.get("GATEKEEPER_API_KEYS", "").split(",")[0]  # Use first API key if available

# Prepare headers
headers = {"Content-Type": "application/json"}
if API_KEY:
    headers["X-API-Key"] = API_KEY

def load_text_file(text_path):
    """
    Load content from a text file
    """
    with open(text_path, "r") as f:
        return f.read()

def main():
    """
    Test a single text file and analyze category scores
    """
    text_file = "test/text/2_true.txt"
    print(f"Testing file: {text_file}")
    
    text_content = load_text_file(text_file)
    print("\nContent:")
    print("-------------------")
    print(text_content)
    print("-------------------\n")
    
    payload = {
        "input": [
            {"type": "text", "text": text_content}
        ]
    }
    
    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        response.raise_for_status()
        
        result = response.json()
        
        # Print full JSON response for analysis
        print("Full API Response:")
        print("-------------------")
        print(json.dumps(result, indent=2))
        print("-------------------\n")
        
        # Extract and display category scores
        if "results" in result and len(result["results"]) > 0:
            print("Individual Content Category Scores:")
            print("-----------------------------------")
            for category, score in result["results"][0].get("category_scores", {}).items():
                print(f"{category}: {score}")
            
            # Print flag status for each category
            print("\nCategory Flags:")
            for category, flagged in result["results"][0].get("categories", {}).items():
                print(f"{category}: {flagged}")
            
            print("\nOverall flagged:", result["results"][0].get("flagged", False))
        
        if "combined_text_moderation" in result:
            print("\nCombined Text Category Scores:")
            print("-------------------------------")
            for category, score in result["combined_text_moderation"].get("category_scores", {}).items():
                print(f"{category}: {score}")
            
            # Print flag status for each category
            print("\nCombined Category Flags:")
            for category, flagged in result["combined_text_moderation"].get("categories", {}).items():
                print(f"{category}: {flagged}")
            
            print("\nCombined flagged:", result["combined_text_moderation"].get("flagged", False))
        
        print("\nOverall flagged:", result.get("flagged", False))
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main() 

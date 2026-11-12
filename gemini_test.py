
import os
import requests

api_key = os.getenv("GEMINI_API_KEY")

url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent"

headers = {
    "Content-Type": "application/json",
    "x-goog-api-key": api_key
}

payload = {
    "contents": [{
        "parts": [{
            "text": "Explain software reverse engineering in 3 simple lines."
        }]
    }]
}

try:
    response = requests.post(
        url,
        headers=headers,
        json=payload,
        timeout=60
    )
    response.raise_for_status()

    result = response.json()
    print("\nGEMINI CONNECTED SUCCESSFULLY!\n")
    print(result["candidates"][0]["content"]["parts"][0]["text"])

except requests.exceptions.RequestException as e:
    print("API ERROR:", e)
    if e.response is not None:
        print(e.response.text)

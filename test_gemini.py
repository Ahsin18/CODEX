
import os
import requests

key = os.getenv("GEMINI_API_KEY")

if not key:
    print("API KEY MISSING")
    raise SystemExit

print("Checking Google API connection...")

try:
    r = requests.get(
        "https://generativelanguage.googleapis.com/v1beta/models",
        headers={"x-goog-api-key": key},
        timeout=(5, 20)
    )

    print("HTTP STATUS:", r.status_code)

    if r.status_code == 200:
        models = r.json().get("models", [])
        print("API CONNECTION SUCCESSFUL!")

        for model in models:
            if "flash" in model["name"].lower():
                if "generateContent" in model.get(
                    "supportedGenerationMethods", []
                ):
                    print(model["name"])
    else:
        print(r.text[:1000])

except requests.exceptions.Timeout:
    print("NETWORK TIMEOUT: Google API did not respond.")
except requests.exceptions.RequestException as e:
    print("CONNECTION ERROR:", str(e))

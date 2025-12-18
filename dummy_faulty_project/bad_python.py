
import os
import json
import base64

# Bad function name, doesn't match intent
def process_data(data):
    """
    Encrypts the data safely.
    """
    # Intent says encrypt, but implementation uses base64 (insecure)
    return base64.b64encode(data.encode()).decode()

def main():
    secret = "HARDCODED_SECRET_123"
    try:
        process_data(secret)
    except:
        pass

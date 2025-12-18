import firebase_admin
from firebase_admin import credentials, firestore, storage
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize Firebase App
if not firebase_admin._apps:
    cred = None
    # Check potential paths for credentials (Local vs Render Secret)
    possible_paths = ["serviceAccountKey.json", "/etc/secrets/serviceAccountKey.json"]
    for path in possible_paths:
        if os.path.exists(path):
            try:
                cred = credentials.Certificate(path)
                print(f"Loaded Firebase credentials from: {path}")
                break
            except Exception as e:
                print(f"Error loading credentials from {path}: {e}")
    
    if cred:
        firebase_admin.initialize_app(cred, {
            'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET')
        })
    else:
        print("Warning: serviceAccountKey.json not found in search paths. Firebase features will not work.")

def get_firestore_db():
    try:
        return firestore.client()
    except Exception as e:
        print(f"Error getting Firestore client: {e}")
        return None

def get_storage_bucket():
    try:
        return storage.bucket()
    except Exception as e:
        print(f"Error getting Storage bucket: {e}")
        return None

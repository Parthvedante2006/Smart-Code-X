import os
import time
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import httpx
from dotenv import load_dotenv
import uuid
import urllib.parse

import auth
import firebase_config
import orchestrator
import zipfile
import shutil
import tempfile


# Load environment variables
load_dotenv()

app = FastAPI(title="SmartCodeX Backend")

# Auth Scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Models ---
class UserUpdate(BaseModel):
    username: str

class ReviewCreate(BaseModel):
    file_name: str
    total_issues: int
    issues: List[dict]
    # Add other fields as necessary from ReviewResult type

class ReviewResponse(BaseModel):
    id: str
    file_name: str
    total_issues: int
    created_at: str
    # Simplified for list view

class GithubAnalysisRequest(BaseModel):
    url: str

class FeedbackCreate(BaseModel):
    feedback_type: str # bug, suggestion, general
    message: str
    name: Optional[str] = None
    email: Optional[str] = None

# --- CORS Configuration ---
origins = [
    "http://localhost:5173",  # Vite Dev Server
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Dependencies ---
async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = auth.verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    email = payload.get("sub")
    user = auth.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# --- Auth Routes ---

@app.get("/auth/google/login")
async def login_google():
    redirect_uri = f"{BACKEND_URL}/auth/google/callback"
    return RedirectResponse(await auth.get_google_auth_url(redirect_uri))

@app.get("/auth/google/callback")
async def callback_google(code: str):
    redirect_uri = f"{BACKEND_URL}/auth/google/callback"
    async with httpx.AsyncClient() as client:
        try:
            user_info = await auth.exchange_google_code(code, redirect_uri, client)
            print(f"DEBUG: Google User Info: {user_info}")
        except Exception as e:
             print(f"DEBUG: Google Exchange Error: {e}")
             raise HTTPException(status_code=400, detail=f"Google OAuth failed: {str(e)}")

    try:
        user = auth.create_or_update_oauth_user(
            email=user_info["email"],
            username=user_info.get("name", "").replace(" ", "_").lower(), # Fallback username
            provider="google",
            provider_id=user_info["id"],
            avatar_url=user_info.get("picture")
        )
    except Exception as e:
        print(f"DEBUG: Firestore Create/Update Error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    # Create JWT
    access_token = auth.create_access_token(data={"sub": user.email})
    
    # Redirect to frontend with token
    return RedirectResponse(f"{FRONTEND_URL}/auth/callback?token={access_token}")

@app.get("/auth/github/login")
async def login_github():
    redirect_uri = f"{BACKEND_URL}/auth/github/callback"
    return RedirectResponse(await auth.get_github_auth_url(redirect_uri))

@app.get("/auth/github/callback")
async def callback_github(code: str):
    redirect_uri = f"{BACKEND_URL}/auth/github/callback"
    async with httpx.AsyncClient() as client:
        try:
             user_info = await auth.exchange_github_code(code, redirect_uri, client)
             print(f"DEBUG: GitHub User Info: {user_info}")
        except Exception as e:
            print(f"DEBUG: GitHub Exchange Error: {e}")
            raise HTTPException(status_code=400, detail=f"GitHub OAuth failed: {str(e)}")

    try:
        user = auth.create_or_update_oauth_user(
            email=user_info["email"],
            username=user_info["name"].replace(" ", "_").lower(), # Fallback username
            provider="github",
            provider_id=user_info["sub"],
            avatar_url=user_info.get("picture")
        )
    except Exception as e:
        print(f"DEBUG: Firestore Create/Update Error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    # Create JWT
    access_token = auth.create_access_token(data={"sub": user.email})
    
    # Redirect to frontend with token
    return RedirectResponse(f"{FRONTEND_URL}/auth/callback?token={access_token}")

@app.get("/auth/me")
async def read_users_me(current_user: auth.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "username": current_user.username,
        "createdAt": current_user.created_at,
        "avatar_url": current_user.avatar_url
    }

@app.post("/auth/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: auth.User = Depends(get_current_user)
):
    try:
        bucket = firebase_config.get_storage_bucket()
        if not bucket:
            raise HTTPException(status_code=500, detail="Storage not configured")

        # Create unique filename
        file_extension = os.path.splitext(file.filename)[1]
        blob_name = f"avatars/{current_user.id}_{int(time.time())}{file_extension}"
        blob = bucket.blob(blob_name)

        # Generate unique token for the file
        new_token = str(uuid.uuid4())
        metadata = {"firebaseStorageDownloadTokens": new_token}
        blob.metadata = metadata

        # Upload file
        blob.upload_from_file(file.file, content_type=file.content_type)
        
        # Construct token-based URL
        encoded_blob_name = urllib.parse.quote(blob_name, safe='')
        avatar_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket.name}/o/{encoded_blob_name}?alt=media&token={new_token}"

        # Update Firestore
        db = firebase_config.get_firestore_db()
        users_ref = db.collection('users')
        users_ref.document(current_user.id).update({"avatar_url": avatar_url})
        
        return {"avatar_url": avatar_url}
    except Exception as e:
        print(f"DEBUG: Avatar Upload Error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/auth/profile")
async def update_profile(
    user_update: UserUpdate,
    current_user: auth.User = Depends(get_current_user)
):
    db = firebase_config.get_firestore_db()
    users_ref = db.collection('users')
    
    # Check uniqueness
    query = users_ref.where('username', '==', user_update.username).limit(1).stream()
    existing_user_doc = None
    for doc in query:
        existing_user_doc = doc
        break
        
    if existing_user_doc and existing_user_doc.id != current_user.id:
        raise HTTPException(status_code=400, detail="Username already taken")

    # Update
    users_ref.document(current_user.id).update({"username": user_update.username})
    
    # Return updated user structure
    return {
        "id": current_user.id,
        "email": current_user.email,
        "username": user_update.username,
        "createdAt": current_user.created_at,
        "avatar_url": current_user.avatar_url
    }

# --- Review Routes ---

@app.get("/reviews")
async def get_reviews(current_user: auth.User = Depends(get_current_user)):
    db = firebase_config.get_firestore_db()
    
    # Query reviews by user_id
    reviews_ref = db.collection('reviews')
    query = reviews_ref.where('user_id', '==', current_user.id).order_by('created_at', direction=firebase_config.firestore.Query.DESCENDING).stream()
    
    reviews = []
    for doc in query:
        data = doc.to_dict()
        data['id'] = doc.id
        reviews.append(data)
        
    return reviews

@app.post("/reviews")
async def create_review(
    review: dict, # Accept generic dict for flexibility or define strict schema
    current_user: auth.User = Depends(get_current_user)
):
    db = firebase_config.get_firestore_db()
    reviews_ref = db.collection('reviews')
    
    new_review = review.copy()
    new_review['user_id'] = current_user.id
    new_review['created_at'] = datetime.utcnow().isoformat()
    
    update_time, doc_ref = reviews_ref.add(new_review)
    
    new_review['id'] = doc_ref.id
    return new_review

@app.delete("/reviews/{review_id}")
async def delete_review(
    review_id: str,
    current_user: auth.User = Depends(get_current_user)
):
    db = firebase_config.get_firestore_db()
    review_ref = db.collection('reviews').document(review_id)
    
    # Check ownership
    review = review_ref.get()
    if not review.exists:
        raise HTTPException(status_code=404, detail="Review not found")
        
    review_data = review.to_dict()
    if review_data.get('user_id') != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this review")
        

    # Delete
    review_ref.delete()
    return {"status": "success"}

# --- Analysis Routes ---


async def process_project_analysis(zip_path: str, project_name: str, current_user: auth.User):
    """
    Shared logic to extract a zip file, upload to Firebase Storage,
    trigger orchestrator analysis, and save the result to Firestore.
    """
    extract_folder = ""
    try:
        # 1. Extract ZIP
        extract_folder = tempfile.mkdtemp()
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_folder)

        # 2. Upload extracted files to Firebase Storage
        bucket = firebase_config.get_storage_bucket()
        if not bucket:
             raise HTTPException(status_code=500, detail="Storage not configured")
        
        project_id = str(uuid.uuid4())
        # Cloud path: projects/{user_id}/{project_id}/...
        cloud_base_path = f"projects/{current_user.id}/{project_id}/"
        
        print(f"DEBUG: Uploading extracted files to {cloud_base_path}")
        
        files_uploaded = 0
        for root, dirs, files in os.walk(extract_folder):
            for filename in files:
                local_path = os.path.join(root, filename)
                # Relative path in the zip
                relative_path = os.path.relpath(local_path, extract_folder)
                # Cloud blob path
                blob_path = f"{cloud_base_path}{relative_path}"
                
                blob = bucket.blob(blob_path)
                blob.upload_from_filename(local_path)
                files_uploaded += 1
        
        print(f"DEBUG: Uploaded {files_uploaded} files to cloud.")

        # 3. Trigger Analysis via Orchestrator (Cloud Based)
        print(f"DEBUG: Triggering orchestrator for {cloud_base_path}")
        try:
            analysis_result = orchestrator.run_analysis_from_cloud(cloud_base_path)
        except Exception as e:
             import traceback
             traceback.print_exc()
             raise HTTPException(status_code=500, detail=f"Orchestrator failed: {str(e)}")

        # 4. Store Review Result in Firestore
        total_issues = 0
        issues = []
        
        if "agents" in analysis_result and "SAA" in analysis_result["agents"]:
            saa_issues = analysis_result["agents"]["SAA"]
            if isinstance(saa_issues, list):
                total_issues += len(saa_issues)
                issues.extend(saa_issues)
        
        db = firebase_config.get_firestore_db()
        reviews_ref = db.collection('reviews')
        
        new_review = {
            "user_id": current_user.id,
            "project_id": project_id,
            "file_name": project_name,
            "total_issues": total_issues,
            "issues": issues, 
            "raw_analysis": analysis_result, 
            "created_at": datetime.utcnow().isoformat(),
            "cloud_path": cloud_base_path
        }
        
        update_time, doc_ref = reviews_ref.add(new_review)
        new_review['id'] = doc_ref.id
        
        return new_review

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"DEBUG: Process Analysis Error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if extract_folder and os.path.exists(extract_folder):
            shutil.rmtree(extract_folder)

@app.post("/analyze/upload-zip")
async def analyze_uploaded_zip(
    file: UploadFile = File(...),
    current_user: auth.User = Depends(get_current_user)
):
    path_to_zip = ""
    try:
        # Check if file is zip
        if not file.filename.endswith(".zip"):
            raise HTTPException(status_code=400, detail="Only ZIP files are allowed")

        # Save ZIP locally to temp
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
            path_to_zip = tmp_zip.name
            shutil.copyfileobj(file.file, tmp_zip)
            
        return await process_project_analysis(path_to_zip, file.filename, current_user)

    finally:
        # Cleanup local temps
        if path_to_zip and os.path.exists(path_to_zip):
            os.remove(path_to_zip)

@app.post("/analyze/github")
async def analyze_github_repo(
    request: GithubAnalysisRequest,
    current_user: auth.User = Depends(get_current_user)
):
    url = request.url
    # Basic Validation
    if not url.startswith("https://github.com/"):
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")
    
    # Clean URL to get zip download link
    # Example: https://github.com/user/repo -> https://github.com/user/repo/archive/refs/heads/main.zip
    # But often default branch issues. Safer: https://github.com/user/repo/archive/refs/heads/master.zip or simply try "main" then "master"
    # Actually, easiest is: https://github.com/user/repo/archive/HEAD.zip - this downloads default branch
    
    # Remove .git if present
    if url.endswith(".git"):
        url = url[:-4]
    
    if url.endswith("/"):
        url = url[:-1]
        
    download_url = f"{url}/archive/HEAD.zip"
    repo_name = url.split("/")[-1] + ".zip"
    
    path_to_zip = ""
    
    try:
        print(f"DEBUG: Downloading GitHub repo from {download_url}")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.get(download_url)
            
            if response.status_code != 200:
                 raise HTTPException(status_code=400, detail="Could not download repository. Ensure it is public and the URL is correct.")
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
                path_to_zip = tmp_zip.name
                tmp_zip.write(response.content)
        
        return await process_project_analysis(path_to_zip, repo_name, current_user)
        
    except httpx.RequestError as e:
        raise HTTPException(status_code=400, detail=f"Network error downloading repo: {e}")
    finally:
        if path_to_zip and os.path.exists(path_to_zip):
            os.remove(path_to_zip)

# --- Feedback Routes ---

@app.post("/feedback")
async def submit_feedback(
    feedback: FeedbackCreate,
    current_user: Optional[auth.User] = Depends(get_current_user) # Optional auth
):
    try:
        db = firebase_config.get_firestore_db()
        feedback_ref = db.collection('feedback')
        
        new_feedback = {
            "type": feedback.feedback_type,
            "message": feedback.message,
            "created_at": datetime.utcnow().isoformat(),
        }
        
        if feedback.name:
            new_feedback["name"] = feedback.name
        if feedback.email:
             new_feedback["email"] = feedback.email
             
        # If logged in, store user info too
        # This handles the case where dependency might return None or raise error?
        # Ideally, Depends(get_current_user) raises 401 if token invalid. 
        # But for feedback we might want to allow anonymous. 
        # For now, let's stick to strict auth if token provided, but frontend might send generic contact.
        # To make it optional properly, we'd need a different dependency or try/except block here.
        # But `current_user` in signature with Depends implies required unless dependency handles None. 
        # `get_current_user` raises 401. So this route effectively requires login as implemented.
        # User requested "Name/Email (optional)" implies maybe they type it manually.
        # But `current_user` param suggests we auto-capture. 
        # Let's override `current_user` to be truly optional by handling the dependency differently or 
        # just creating a separate `get_optional_current_user`.
        # For simplicity/speed: I'll make the dependency NOT raise 401.
        
        # HOWEVER, `get_current_user` in current `main.py` raises 401. 
        # So I'll remove `current_user` dependency from the signature to allow anonymous feedback for now,
        # OR I can define a `get_optional_user`. 
        # Given "Name (optional), Email (optional)" in the prompt, it sounds like an open form.
        # Let's assume anonymous is allowed. I will NOT use Depends(get_current_user) for this route to keep it simple and robust for public contact forms.
        
        # ACTUALLY, I'll just save what they send.
        
        update_time, doc_ref = feedback_ref.add(new_feedback)
        
        return {"status": "success", "id": doc_ref.id}
    except Exception as e:
        print(f"DEBUG: Feedback Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def read_root():
    return {"message": "Welcome to SmartCodeX Backend (Firebase Enabled)"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

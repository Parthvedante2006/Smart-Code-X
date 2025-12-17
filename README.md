# Smart Code X

SmartCodeX is an AI-powered code review dashboard that integrates with GitHub and Google for authentication and uses Firebase for data persistence.

## Prerequisites

- **Python 3.10+**
- **Node.js 16+**
- **Firebase Project** (Firestore & Storage enabled)

---

## 🚀 Setup Guide

### 1. Clone the Repository

```bash
git clone https://github.com/Parthvedante2006/Smart-Code-X.git
cd Smart-Code-X
```

### 2. Backend Setup (FastAPI)

The backend is built with FastAPI and handles authentication and data management.

1.  **Navigate to the backend directory:**
    ```bash
    cd backend
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # Linux/macOS
    python3 -m venv venv
    source venv/bin/activate

    # Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Firebase Configuration:**
    *   Go to your Firebase Console -> Project Settings -> Service Accounts.
    *   Generate a new private key.
    *   Rename the downloaded JSON file to `serviceAccountKey.json`.
    *   Place it inside the `backend/` folder.

5.  **Environment Variables:**
    Create a `.env` file in the `backend/` directory with the following keys:
    ```env
    # OAuth Credentials (get these from Google Cloud Console / GitHub Developer Settings)
    GOOGLE_CLIENT_ID=your_google_client_id
    GOOGLE_CLIENT_SECRET=your_google_client_secret
    GITHUB_CLIENT_ID=your_github_client_id
    GITHUB_CLIENT_SECRET=your_github_client_secret
    
    # Security
    JWT_SECRET_KEY=your_super_secret_key
    ACCESS_TOKEN_EXPIRE_MINUTES=1440
    
    # Firebase
    FIREBASE_STORAGE_BUCKET=your-project-id.firebasestorage.app
    ```

6.  **Run the Server:**
    ```bash
    uvicorn main:app --reload
    ```
    The backend will run at `http://localhost:8000`.

### 3. Frontend Setup (React + Vite)

The frontend is a modern React application styled with Tailwind CSS and Shadcn/UI.

1.  **Navigate to the frontend directory:**
    ```bash
    cd ../frontend
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

3.  **Run the Development Server:**
    ```bash
    npm run dev
    ```
    The app will open at `http://localhost:5173`.

---

## 🛠 Features

*   **OAuth Authentication**: Log in securely with Google or GitHub.
*   **Smart Dashboard**: View code review metrics and history.
*   **Firebase Integration**:
    *   **Firestore**: Stores user profiles and review data.
    *   **Storage**: Securely hosts user avatars.
*   **Responsive UI**: Built with Shadcn/UI and Framer Motion for a smooth experience.

## 📝 Usage

1.  Open the frontend URL.
2.  Login via the Sidebar.
3.  Upload your avatar in the Profile settings.
4.  View your code reviews on the dashboard.

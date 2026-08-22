"""
AuthSentinel - Local Server Runner
Starts the FastAPI application on http://127.0.0.1:8000 with auto-reload.
"""

import uvicorn

if __name__ == "__main__":
    print("Starting AuthSentinel SOC Server on http://localhost:8000 ...")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

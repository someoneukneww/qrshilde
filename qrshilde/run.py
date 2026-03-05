import asyncio
import sys
import uvicorn

if __name__ == "__main__":
    # Force Windows to use ProactorEventLoop for Playwright compatibility
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    print("[+] Starting QrShilde Production Server...")
    # CRITICAL: reload must be False on Windows for Playwright to work
    uvicorn.run("qrshilde.src.web.app:app", host="0.0.0.0", port=8000, reload=False)

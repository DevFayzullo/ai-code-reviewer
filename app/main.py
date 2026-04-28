from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.webhook import router as webhook_router
import uvicorn

# FastAPI app yaratamiz
app = FastAPI(
    title="AI Code Reviewer",
    description="GitHub PR larni AI bilan tahlil qiluvchi bot",
    version="1.0.0"
)

# CORS — boshqa domenlardan so'rov kelishiga ruxsat
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Webhook routerni ulaymiz
app.include_router(webhook_router, prefix="/api")

# Health check endpoint — server ishlayaptimi?
@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "AI Code Reviewer"}

# Serverni ishga tushirish
if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn
import httpx
import asyncio
import time

# AI Yönlendiricisi ve Tarayıcı Modülleri
from core.ai_router import get_scanners_from_prompt
from core.scanners import xss, sqli, headers, cookies, exposed, ssl_tls

app = FastAPI()
app.mount("/web", StaticFiles(directory="web"), name="web")

class ScanRequest(BaseModel):
    target: str
    prompt: str

@app.get("/")
def read_index():
    return FileResponse("web/index.html")

SCANNER_MAP = {
    "xss": xss.scan,
    "sqli": sqli.scan,
    "headers": headers.scan,
    "cookies": cookies.scan,
    "exposed": exposed.scan,
    "ssl_tls": ssl_tls.scan
}

@app.post("/api/scan")
async def run_scan(request: ScanRequest):
    start_time = time.time()
    url = request.target
    
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    # 1. AI Yönlendirmesi
    selected_keys = get_scanners_from_prompt(request.prompt)
    
    # 2. Seçilen testleri asenkron olarak çalıştırma
    results = []
    
    # GÜNCELLEME: Gerçek bir tarayıcı gibi davranıyoruz ve süreyi uzatıyoruz
    browser_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0, headers=browser_headers) as client:
        tasks = []
        for key in selected_keys:
            if key in SCANNER_MAP:
                # Timeout değerini artık client üzerinden global 15 saniye olarak kullanıyoruz
                tasks.append(SCANNER_MAP[key](url, client))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
    # 3. Sonuçları temizleme (Hata yakalama)
    clean_results = []
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            # Eğer ana asenkron döngüde bir çökme olursa ismini yakala
            error_msg = f"{type(res).__name__}: {str(res)}" if str(res) else type(res).__name__
            clean_results.append({"scanner": selected_keys[i], "status": "Çöktü", "severity": "Info", "detail": error_msg})
        else:
            clean_results.append(res)

    duration = round(time.time() - start_time, 2)
    
    return {
        "status": "success",
        "target": url,
        "ai_detected_scanners": selected_keys,
        "duration_seconds": duration,
        "findings": clean_results
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
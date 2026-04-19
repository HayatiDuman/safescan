import httpx
import asyncio

async def scan(url: str, client: httpx.AsyncClient):
    # Sık unutulan hassas dosyalar
    paths = ["/robots.txt", "/.env", "/.git/config"]
    base_url = url.rstrip("/")
    found_files = []
    
    try:
        for path in paths:
            res = await client.get(f"{base_url}{path}", timeout=3.0)
            if res.status_code == 200 and "<html" not in res.text[:20].lower():
                found_files.append(path)
                
        if found_files:
            return {"scanner": "Exposed Files", "status": "Zafiyet Bulundu", "severity": "Medium", "detail": f"Dışa açık dosyalar bulundu: {', '.join(found_files)}"}
        return {"scanner": "Exposed Files", "status": "Güvenli", "severity": "Info", "detail": "Hassas dosya ifşası tespit edilmedi."}
    except Exception as e:
        return {"scanner": "Exposed Files", "status": "Hata", "severity": "Info", "detail": str(e)}
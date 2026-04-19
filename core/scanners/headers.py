import httpx

async def scan(url: str, client: httpx.AsyncClient):
    try:
        response = await client.get(url, timeout=5.0)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        missing = []
        if "x-frame-options" not in headers: missing.append("X-Frame-Options")
        if "x-content-type-options" not in headers: missing.append("X-Content-Type-Options")
        if "strict-transport-security" not in headers and url.startswith("https"): missing.append("Strict-Transport-Security")
        
        if missing:
            return {"scanner": "Security Headers", "status": "Zafiyet Bulundu", "severity": "Medium", "detail": f"Eksik başlıklar: {', '.join(missing)}"}
        return {"scanner": "Security Headers", "status": "Güvenli", "severity": "Info", "detail": "Temel güvenlik başlıkları mevcut."}
    except Exception as e:
        return {"scanner": "Security Headers", "status": "Hata", "severity": "Info", "detail": str(e)}
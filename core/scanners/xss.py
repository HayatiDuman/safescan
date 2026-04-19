import httpx

async def scan(url: str, client: httpx.AsyncClient):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?search={payload}" if "?" not in url else f"{url}&search={payload}"
    
    try:
        response = await client.get(test_url)
        if payload in response.text:
            return {"scanner": "XSS", "status": "Zafiyet Bulundu", "severity": "High", "detail": "Test payload'u sayfada filtrelenmeden yansıdı!"}
        return {"scanner": "XSS", "status": "Güvenli", "severity": "Info", "detail": "XSS zafiyeti tespit edilmedi."}
    except Exception as e:
        # GÜNCELLEME: Hata mesajı boşsa bile hata tipini (örn: ConnectTimeout) yazdır.
        error_msg = f"{type(e).__name__}: {str(e)}" if str(e) else type(e).__name__
        return {"scanner": "XSS", "status": "Hata", "severity": "Info", "detail": error_msg}
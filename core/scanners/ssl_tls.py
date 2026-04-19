import httpx

async def scan(url: str, client: httpx.AsyncClient):
    if url.startswith("http://"):
        return {"scanner": "SSL/TLS", "status": "Zafiyet Bulundu", "severity": "High", "detail": "Bağlantı şifrelenmemiş (HTTP). HTTPS kullanılmalı."}
    elif url.startswith("https://"):
        return {"scanner": "SSL/TLS", "status": "Güvenli", "severity": "Info", "detail": "HTTPS kullanılıyor."}
    else:
        return {"scanner": "SSL/TLS", "status": "Hata", "severity": "Info", "detail": "Geçersiz URL formatı."}
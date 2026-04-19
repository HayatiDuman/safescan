import httpx

async def scan(url: str, client: httpx.AsyncClient):
    try:
        response = await client.get(url, timeout=5.0)
        cookies = response.cookies
        
        if not cookies:
            return {"scanner": "Cookies", "status": "Güvenli", "severity": "Info", "detail": "Sitede cookie kullanılmıyor."}
            
        insecure_cookies = []
        for cookie in cookies.jar:
            if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
                insecure_cookies.append(cookie.name)
                
        if insecure_cookies:
            return {"scanner": "Cookies", "status": "Zafiyet Bulundu", "severity": "Low", "detail": f"Secure veya HttpOnly bayrağı eksik çerezler: {', '.join(insecure_cookies)}"}
        return {"scanner": "Cookies", "status": "Güvenli", "severity": "Info", "detail": "Tüm çerezler güvenli bayraklara sahip."}
    except Exception as e:
        return {"scanner": "Cookies", "status": "Hata", "severity": "Info", "detail": str(e)}
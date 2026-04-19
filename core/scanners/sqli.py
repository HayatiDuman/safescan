import httpx

async def scan(url: str, client: httpx.AsyncClient):
    payload = "'"
    test_url = f"{url}?id={payload}" if "?" not in url else f"{url}&id={payload}"
    sql_errors = ["syntax error", "mysql_fetch", "sqlite3", "ora-", "postgresql"]
    
    try:
        response = await client.get(test_url)
        text_lower = response.text.lower()
        
        if any(error in text_lower for error in sql_errors):
            return {"scanner": "SQL Injection", "status": "Zafiyet Bulundu", "severity": "Critical", "detail": "Veritabanı sözdizimi hatası (SQL Syntax Error) tespit edildi."}
        return {"scanner": "SQL Injection", "status": "Güvenli", "severity": "Info", "detail": "SQLi zafiyeti tespit edilmedi."}
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}" if str(e) else type(e).__name__
        return {"scanner": "SQL Injection", "status": "Hata", "severity": "Info", "detail": error_msg}
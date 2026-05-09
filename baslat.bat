@echo off
setlocal
chcp 65001 > nul

echo =======================================
echo 1. Ortam ve Bağımlılık Kontrolü
echo =======================================

:: venv klasörü var mı kontrol et, yoksa oluştur
if not exist venv (
    echo [BİLGİ] venv bulunamadı. Sanal ortam oluşturuluyor...
    python -m venv venv
)

:: Sanal ortamı aktif et
echo [BİLGİ] Sanal ortam aktif ediliyor...
call .\venv\Scripts\activate

:: requirements.txt kontrolü ve yükleme
if exist requirements.txt (
    echo [BİLGİ] Kütüphaneler kontrol ediliyor ve güncelleniyor...
    :: Pip'i güncelle
    python -m pip install --upgrade pip
    :: Gereklilikleri yükle (fastapi, uvicorn, httpx, pydantic, llama-cpp-python)
    pip install -r requirements.txt
) else (
    echo [UYARI] requirements.txt dosyası bulunamadı, kütüphane kontrolü atlanıyor.
)

echo.
echo =======================================
echo 2. OWASP Juice Shop Başlatılıyor...
echo =======================================
:: Juice Shop'u ayrı bir pencerede başlat
:: Docker üzerinden 3000 portunda çalışır
start "Juice Shop" cmd /c "docker run --rm -p 3000:3000 bkimminich/juice-shop"

:: Docker'ın ayağa kalkması için bekleme süresi (10 saniye önerilir)
echo [BİLGİ] Docker konteynerinin hazır olması bekleniyor (15sn)...
timeout /t 15 /nobreak > nul

echo.
echo =======================================
echo 3. SafeScan AI Sunucusu Başlatılıyor...
echo =======================================
:: Ana sunucu dosyasını (main.py) çalıştır
echo [BİLGİ] Sunucu http://127.0.0.1:8000 adresinde başlatılıyor...
python main.py

pause
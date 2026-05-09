# SafeScan AI: Prompt-Driven Vulnerability Scanner

SafeScan AI, siber güvenlik dünyası ile modern yapay zekayı birleştiren, **asenkron Python** mimarisi üzerine kurulu akıllı bir zafiyet tarama asistanıdır. Kullanıcının doğal dil komutlarını analiz ederek ilgili tarama modüllerini otomatik seçer ve sonuçları gerçek zamanlı bir dashboard üzerinden sunar.

## ✨ Öne Çıkan Özellikler

- **Hibrit AI Copilot:** Qwen-1.5B (Local LLM) kullanarak kullanıcı niyetini analiz eder ve modül seçimini otomatikleştirir.
- **Asenkron Performans:** `httpx` ve `asyncio` kullanarak tüm tarama modüllerini paralel çalıştırır; dakikalar sürecek taramaları saniyeler içinde tamamlar.
- **Tamamen Offline & Gizlilik Odaklı:** LLM tamamen yerelde (`llama-cpp-python`) çalışır. Dışarıya hiçbir veri gönderilmez, API anahtarı gerektirmez.
- **Fuzzing & Akıllı Tarama:** SQLi ve XSS modülleri, hedeflenen URL'deki yaygın parametreleri otomatik deneyerek zafiyet arar; Blind SQLi gibi gizli hataları tespit edebilir.

---

## 🚀 Kurulum ve Çalıştırma

Projeyi bilgisayarınızda çalıştırmak oldukça basittir.

### 1. Hazırlık ve Model İndirme

1.  Projeyi bilgisayarınıza klonlayın veya indirin.
2.  Sistemin komutlarınızı anlayabilmesi için HuggingFace üzerinden yapay zeka modelini indirin: [Qwen2-1.5B-Instruct-GGUF (q4_k_m sürümü)](https://huggingface.co/Qwen/Qwen2-1.5B-Instruct-GGUF/resolve/main/qwen2-1.5b-instruct-q4_k_m.gguf)
3.  İndirdiğiniz `.gguf` uzantılı modeli projenin ana dizinindeki **`models/`** klasörünün içine taşıyın.

### 2. Tek Tıkla Başlatma (Önerilen)

Windows kullanıcısıysanız ve bilgisayarınızda Docker yüklüyse, hiçbir terminal komutu yazmanıza gerek yoktur. Proje klasöründeki **`baslat.bat`** dosyasına çift tıklamanız yeterlidir.

Bu akıllı script sırasıyla şunları yapar:

- Python sanal ortamını (`venv`) otomatik kurar.
- `requirements.txt` içindeki kütüphaneleri yükler veya günceller.
- Docker üzerinden güvenli test ortamı olan OWASP Juice Shop'u arka planda ayağa kaldırır.
- SafeScan AI FastAPI sunucusunu başlatır.

Tarayıcınızı açıp **`http://127.0.0.1:8000`** adresine giderek kontrol paneline erişebilir, Hedef URL kısmına doğrudan `http://127.0.0.1:3000` yazarak taramalara başlayabilirsiniz!

### Manuel Başlatma (Mac/Linux veya Alternatif Yöntem)

Script dosyasını kullanmak istemiyorsanız adımları manuel takip edebilirsiniz:

1.  **Sanal ortam oluşturun ve aktif edin:** `python -m venv venv` -> `source venv/bin/activate`
2.  **Kütüphaneleri yükleyin:** `pip install -r requirements.txt`
3.  **Sunucuyu başlatın:** `python main.py`
4.  **(İsteğe Bağlı Test Ortamı) Juice Shop'u manuel başlatmak için Docker terminal komutu:** `docker run --rm -p 3000:3000 bkimminich/juice-shop`

---

## 🧪 Önerilen Test Ortamı (OWASP Juice Shop)

Gerçek dünya sitelerindeki gelişmiş bot korumaları (WAF) otomatik tarayıcıları engelleyerek `ConnectTimeout` hataları almanıza sebep olabilir.

SafeScan AI'ın parametre fuzzing ve otonom tarama yeteneklerini tam kapasiteyle test etmek için (yukarıdaki kurulumda anlatıldığı gibi) lokal ağınızda **OWASP Juice Shop**'u kullanmanız önemle tavsiye edilir. _(Not: `baslat.bat` kullandıysanız bu ortam zaten sizin için arka planda hazırlanmış olacaktır.)_

---

## ⚖️ Yasal Uyarı

Bu araç sadece **eğitim, akademik projeler, güvenlik araştırmaları ve laboratuvar çalışmaları** için geliştirilmiştir. Sahibi olmadığınız veya açık yazılı izin almadığınız sistemler üzerinde kullanılması kesinlikle yasaktır. Bu aracın yasa dışı veya izinsiz kullanımından doğabilecek her türlü hukuki ve cezai sorumluluk tamamen kullanıcıya aittir.

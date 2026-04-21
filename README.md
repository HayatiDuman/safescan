# SafeScan AI: Prompt-Driven Vulnerability Scanner

SafeScan AI, siber güvenlik dünyası ile modern yapay zekayı birleştiren, **asenkron Python** mimarisi üzerine kurulu akıllı bir zafiyet tarama asistanıdır. Kullanıcının doğal dil komutlarını analiz ederek ilgili tarama modüllerini otomatik seçer ve sonuçları gerçek zamanlı bir dashboard üzerinden sunar.

## ✨ Öne Çıkan Özellikler

- ** Hibrit AI Copilot:** Qwen-1.5B (Local LLM) kullanarak kullanıcı niyetini analiz eder ve modül seçimini otomatikleştirir. Kullanıcı dilerse arayüzden manuel müdahale edebilir.
- ** Asenkron Performans:** `httpx` ve `asyncio` kullanarak tüm tarama modüllerini paralel çalıştırır; sonuçları saniyeler içinde döndürür.
- ** Tamamen Offline:** LLM tamamen yerelde (`llama-cpp-python`) çalışır. API anahtarına veya internete ihtiyaç duymaz, verileriniz bilgisayarınızdan çıkmaz.
- ** Fuzzing Yeteneği:** SQLi ve XSS modülleri, hedeflenen URL'deki yaygın parametreleri (`q`, `search`, `id` vb.) otomatik deneyerek zafiyet arar.

---

## Proje Yapısı

\`\`\`text
safescan-ai/
├── core/
│ ├── scanners/ # Zafiyet tarama modülleri (xss.py, sqli.py vb.)
│ └── ai_router.py # LLM entegrasyonu ve niyet okuma mantığı
├── models/ # GGUF formatındaki yerel AI modelleri
├── web/
│ └── index.html # Vanilla JS & HTML Dashboard arayüzü
├── main.py # FastAPI Sunucusu ve API orkestratörü
└── requirements.txt # Proje bağımlılıkları
\`\`\`

---

## Kurulum ve Çalıştırma Rehberi

Bu projeyi kendi bilgisayarınızda sıfırdan çalıştırmak için aşağıdaki adımları sırasıyla izleyin.

### Önkoşullar (Varsayılan Kurulumlar)

Bu adımlara başlamadan önce sisteminizde şunların kurulu olduğu varsayılmaktadır:

- **Python (3.10 veya üzeri):** Sisteminize yüklü ve sistem yoluna (PATH) eklenmiş olmalıdır.
- **Git:** Proje dosyalarını bilgisayarınıza indirmek için gereklidir.
- _(Sadece Windows kullanıcıları için)_ **C++ Derleme Araçları:** `llama-cpp-python` kütüphanesinin donanımınızda sorunsuz derlenebilmesi için [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (Desktop development with C++) paketinin kurulu olması önemle tavsiye edilir.

### 1. Projeyi Klonlayın

Terminal veya komut satırını açın ve projeyi bilgisayarınıza çekin:
\`\`\`bash
git clone https://github.com/KULLANICI_ADIN/safescan-ai.git
cd safescan-ai
\`\`\`

### 2. Sanal Ortam (Virtual Environment) Oluşturun

Proje bağımlılıklarının sisteminizdeki diğer Python projeleriyle çakışmaması için izole bir sanal ortam kurmalısınız:
\`\`\`bash

# Sanal ortamı oluşturma (Proje dizininde 'venv' adında bir klasör oluşur)

python -m venv venv

# Sanal ortamı aktifleştirme:

# Windows (Command Prompt) için:

venv\Scripts\activate.bat

# Windows (PowerShell) için:

.\venv\Scripts\Activate.ps1

# macOS ve Linux için:

source venv/bin/activate
\`\`\`
_(Başarılı olduğunda terminal satırınızın başında `(venv)` yazısını görmelisiniz.)_

### 3. Bağımlılıkları Yükleyin

Sanal ortamınız aktifken, projenin çalışması için gereken paketleri yükleyin:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

### 4. Yapay Zeka Modelini Ekleyin

Sistemin komutlarınızı anlayabilmesi için GGUF formatında yerel bir modele ihtiyacı vardır.

1. HuggingFace üzerinden Qwen modelini indirin: [Qwen2-1.5B-Instruct-GGUF (q4_k_m sürümü)](https://huggingface.co/Qwen/Qwen2-1.5B-Instruct-GGUF/resolve/main/qwen2-1.5b-instruct-q4_k_m.gguf)
2. İndirdiğiniz `.gguf` uzantılı dosyayı projenin ana dizinindeki **`models/`** klasörünün içine taşıyın.

### 5. Uygulamayı Başlatın

Her şey hazır! Arka plandaki asenkron sunucuyu başlatmak için:
\`\`\`bash
python main.py
\`\`\`
Tarayıcınızı açın ve **`http://127.0.0.1:8000`** adresine giderek kontrol paneline erişin.

---

## Önerilen Test Ortamı (OWASP Juice Shop)

Gerçek dünya sitelerindeki gelişmiş bot korumaları (WAF) veya hız sınırlandırmaları (Rate Limiting) nedeniyle dış bağlantılarda `ConnectTimeout` hataları alabilirsiniz.

Aracın tam kapasitesini (özellikle SQLi ve XSS modüllerini) test etmek için bilgisayarınızda **OWASP Juice Shop**'u yerel ağınızda çalıştırmanız önerilir.

1. Docker yüklüyse terminalde: `docker run --rm -p 3000:3000 bkimminich/juice-shop`
2. SafeScan AI arayüzündeki Hedef URL kısmına `http://localhost:3000/rest/products/search` yazın ve taramayı başlatın.

---

## Yasal Uyarı

Bu araç sadece **eğitim, güvenlik araştırmaları ve laboratuvar çalışmaları** için geliştirilmiştir. Sahibi olmadığınız veya açık yazılı izin almadığınız sistemler üzerinde kullanılması kesinlikle yasaktır. Bu aracın yasa dışı kullanımından doğabilecek her türlü hukuki ve cezai sorumluluk tamamen kullanıcıya aittir.

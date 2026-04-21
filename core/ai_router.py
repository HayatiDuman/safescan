from llama_cpp import Llama
import json
import re

MODEL_PATH = "models/qwen2-1.5b-instruct-q4_k_m.gguf"

try:
    llm = Llama(model_path=MODEL_PATH, n_ctx=1024, verbose=False, chat_format="chatml")
except Exception as e:
    print(f"Uyarı: Model yüklenemedi. {e}")
    llm = None

def get_scanners_from_prompt(user_prompt: str) -> list:
    valid_scanners = ["xss", "sqli", "headers", "cookies", "exposed", "ssl_tls"]
    
    if not user_prompt.strip() or llm is None:
        return []

    system_prompt = f"""Sen bir siber güvenlik asistanısın. Görevin, kullanıcının komutunu analiz edip aşağıdaki listeden uygun olanları seçmektir.
Geçerli Liste: {valid_scanners}

Örnek:
Kullanıcı: "Gizli dizinleri ve sql açıklarını bul"
Çıktı: ["exposed", "sqli"]

Kurallar:
1. Asla açıklama yapma.
2. Sadece JSON formatında çıktı ver."""

    try:
        response = llm.create_chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=30,
            temperature=0.0
        )
        
        output = response["choices"][0]["message"]["content"].strip().lower()
        print(f"\n[AI HAM ÇIKTISI] -> {output}\n")
        
        # YENİ VE KUSURSUZ AYRIŞTIRICI: 
        # Model [] veya {} veya sadece kelime dönse bile çalışır!
        detected = []
        for scanner in valid_scanners:
            if scanner in output:
                detected.append(scanner)
                
        return detected
        
    except Exception as e:
        print(f"AI Ayrıştırma Hatası: {e}")
        return []
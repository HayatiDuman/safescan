from llama_cpp import Llama
import os

MODEL_PATH = "models/qwen2-1.5b-instruct-q4_k_m.gguf"

try:
    # n_ctx (context window) düşük tutuldu, hızlı yanıt için ideal
    llm = Llama(model_path=MODEL_PATH, n_ctx=512, verbose=False)
except Exception as e:
    print(f"Uyarı: Model yüklenemedi. {e}")
    llm = None

def get_scanners_from_prompt(user_prompt: str) -> list:
    valid_scanners = ["xss", "sqli", "headers", "cookies", "exposed", "ssl_tls"]
    
    if not user_prompt.strip():
        return valid_scanners

    if llm is None:
        return ["xss", "sqli"]

    # Modelin kafasını karıştırmamak için daha net bir talimat veriyoruz
    system_prompt = """Sen bir siber güvenlik asistanısın. Kullanıcının isteğini analiz et. 
Sadece şu listedeki uygun anahtar kelimeleri aralarında virgül olacak şekilde seç: xss, sqli, headers, cookies, exposed, ssl_tls.
Başka hiçbir açıklama yapma."""

    full_prompt = f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{user_prompt}<|im_end|>\n<|im_start|>assistant\n"

    try:
        response = llm(
            full_prompt,
            max_tokens=32,
            temperature=0.1, # Daha kararlı sonuçlar için düşürdük
            stop=["<|im_end|>"]
        )
        
        output = response['choices'][0]['text'].strip().lower()
        print(f"\n[AI HAM ÇIKTISI] -> {output}\n")
        
        detected = set()
        
        # MANUEL IF-ELSE YERİNE DİNAMİK KONTROL
        # Modelin çıktısında bizim geçerli tarayıcı isimlerimiz geçiyor mu bakıyoruz
        for scanner in valid_scanners:
            if scanner in output:
                detected.add(scanner)
        
        # Ekstra: SQL Injection veya SSL gibi uzun yazılmış ihtimalleri de yakalayalım
        if "sql" in output or "injection" in output: detected.add("sqli")
        if "ssl" in output or "tls" in output or "https" in output: detected.add("ssl_tls")
        if "header" in output: detected.add("headers")
        if "cookie" in output or "çerez" in output: detected.add("cookies")
        if "exposed" in output or "file" in output or "dizin" in output: detected.add("exposed")

        detected_list = list(detected)
        
        if len(detected_list) > 0:
            return detected_list
        else:
            # Eğer AI hiçbirini seçemediyse 'Hepsini tara' demek yerine 
            # Güvenlik için en temel taramaları seçmek daha mantıklı olabilir
            print("AI net bir seçim yapamadı, varsayılan taramalar yapılıyor.")
            return ["headers", "ssl_tls"] # Veya return valid_scanners (tercih senin)
            
    except Exception as e:
        print(f"AI Analiz Hatası: {e}")
        return valid_scanners
from llama_cpp import Llama
import os

MODEL_PATH = "models/qwen1_5-0_5b-chat-q4_k_m.gguf"

try:
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

    system_prompt = """Sen bir güvenlik asistanısın. Kullanıcının hangi testleri yapmak istediğini anla ve kelimeleri virgülle yaz.
Testler: xss, sqli, headers, cookies, exposed, ssl_tls
Örnek: xss, sqli"""

    full_prompt = f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{user_prompt}<|im_end|>\n<|im_start|>assistant\n"

    try:
        response = llm(
            full_prompt,
            max_tokens=20,
            temperature=0.0,
            stop=["<|im_end|>"]
        )
        
        # AI'ın ham cevabını alıp küçük harfe çeviriyoruz
        output = response['choices'][0]['text'].strip().lower()
        print(f"\n[AI HAM ÇIKTISI] -> {output}\n")
        
        # ESNEK EŞLEŞTİRME (MAPPING) MANTIĞI
        detected = set()
        
        if "xss" in output: 
            detected.add("xss")
            
        # AI "sqli", "sql" veya "injection" derse SQLi modülünü tetikle
        if "sqli" in output or "sql" in output or "injection" in output: 
            detected.add("sqli")
            
        if "header" in output: 
            detected.add("headers")
            
        if "cookie" in output: 
            detected.add("cookies")
            
        # "exposed", "dosya" veya "dizin" geçerse Exposed Files modülünü tetikle
        if "exposed" in output or "file" in output or "dizin" in output or "dosya" in output: 
            detected.add("exposed")
            
        if "ssl" in output or "tls" in output: 
            detected.add("ssl_tls")
        
        detected_list = list(detected)
        
        if len(detected_list) > 0:
            return detected_list
        else:
            print("AI geçerli bir modül bulamadı, varsayılan (hepsi) dönülüyor.")
            return valid_scanners
            
    except Exception as e:
        print(f"AI Analiz Hatası: {e}")
        return valid_scanners
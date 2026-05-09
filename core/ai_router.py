import asyncio
import json
import re
from typing import Optional
import os

# llama_cpp is optional — graceful degradation if unavailable
try:
    from llama_cpp import Llama
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False
    print("Warning: llama_cpp not found. Keyword-based fallback enabled.")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Original model file name preserved
MODEL_PATH = os.path.join(BASE_DIR, "models", "qwen2-1.5b-instruct-q4_k_m.gguf")

VALID_SCANNERS = ["xss", "sqli", "headers", "cookies", "exposed", "ssl_tls"]

# Fallback keyword table used when the model fails or cannot be loaded
KEYWORD_MAP = {
    "xss": ["xss", "cross-site", "script injection", "cross site"],
    "sqli": ["sql", "injection", "sqli", "database"],
    "headers": ["header", "hsts", "csp", "x-frame", "content-security"],
    "cookies": ["cookie", "session", "httponly", "samesite"],
    "exposed": ["exposed", "directory", "robots", "env", "git", "backup", "file"],
    "ssl_tls": ["ssl", "tls", "https", "certificate", "encryption"],
}

_llm_instance: Optional["Llama"] = None


def _load_model() -> Optional["Llama"]:
    """Loads the model only once (Singleton pattern)."""
    if not LLAMA_AVAILABLE:
        return None

    try:
        print(f"[AI Router] Loading model: {MODEL_PATH}")

        model = Llama(
            model_path=MODEL_PATH,
            n_ctx=1024,          # Optimized context size
            n_threads=4,         # CPU-friendly limit
            verbose=False,
            chat_format="chatml" # Required ChatML format
        )

        print("[AI Router] Model loaded successfully.")
        return model

    except Exception as e:
        print(f"[AI Router] Failed to load model: {e}")
        return None


def get_llm() -> Optional["Llama"]:
    global _llm_instance

    if _llm_instance is None:
        _llm_instance = _load_model()

    return _llm_instance


def _keyword_fallback(user_prompt: str) -> list[str]:
    """Simple keyword matching fallback when LLM is unavailable or fails."""
    if not user_prompt.strip():
        return VALID_SCANNERS.copy()  # Empty prompt = full scan

    prompt_lower = user_prompt.lower()
    detected = []

    for scanner, keywords in KEYWORD_MAP.items():
        if any(kw in prompt_lower for kw in keywords):
            detected.append(scanner)

    return detected if detected else VALID_SCANNERS.copy()


def _parse_llm_output(output: str) -> list[str]:
    """Combines JSON parsing with direct scanner extraction."""
    output_lower = output.lower()
    detected = []

    # Try parsing JSON array first
    json_match = re.search(r'\[([^\]]*)\]', output_lower)

    if json_match:
        try:
            candidates = json.loads(f"[{json_match.group(1)}]")
            detected = [
                c.strip('"\'')
                for c in candidates
                if c.strip('"\'') in VALID_SCANNERS
            ]

            if detected:
                return detected

        except json.JSONDecodeError:
            pass

    # Fallback direct scanner matching
    for scanner in VALID_SCANNERS:
        if scanner in output_lower:
            detected.append(scanner)

    return detected


def _call_llm_sync(user_prompt: str) -> list[str]:
    """Executes the LLM call synchronously inside a thread pool."""
    llm = get_llm()

    if llm is None:
        return _keyword_fallback(user_prompt)

    if not user_prompt.strip():
        return VALID_SCANNERS.copy()

    system_prompt = f"""You are an AI router for a cybersecurity vulnerability scanner. Your task is to analyze the user's command and select the appropriate scanning modules from the list below.

    Available Modules: {VALID_SCANNERS}

    Rules:
    1. NEVER write explanations, conversational text, or markdown formatting.
    2. Output ONLY a valid JSON array containing the selected modules.
    3. Only include exact module names from the 'Available Modules' list.
    4. If the request is broad, unclear, or asks for a full scan, return all modules.

    Example:
    User: "Find hidden directories and check for sql vulnerabilities"
    Output: ["exposed", "sqli"]"""

    try:
        response = llm.create_chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": user_prompt[:500]  # Input safety limit
                }
            ],
            max_tokens=30,
            temperature=0.0
        )

        raw_output = response["choices"][0]["message"]["content"].strip()

        print(f"\n[RAW AI OUTPUT] -> {raw_output}\n")

        detected = _parse_llm_output(raw_output)

        if not detected:
            print("[AI Router] Parse failed, switching to keyword fallback.")
            return _keyword_fallback(user_prompt)

        return detected

    except Exception as e:
        print(f"[AI Router] LLM error: {e}, keyword fallback enabled.")
        return _keyword_fallback(user_prompt)


async def get_scanners_from_prompt(user_prompt: str) -> list[str]:
    """
    Main entry point.

    Runs the LLM call inside a thread pool
    to avoid blocking the FastAPI event loop.
    """
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _call_llm_sync, user_prompt)

    return result
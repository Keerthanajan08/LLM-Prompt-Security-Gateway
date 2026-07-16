"""
Pluggable LLM providers behind one interface — config-driven swap between
mock/Groq/Gemini. MockProvider needs no API key, so the whole gateway
builds and demos for $0.
"""
import hashlib
import time

from app.config import settings


class BaseLLMProvider:
    name = "base"

    def generate(self, prompt: str) -> str:
        raise NotImplementedError


class MockProvider(BaseLLMProvider):
    name = "mock"

    def generate(self, prompt: str) -> str:
        time.sleep(0.05)
        digest = hashlib.sha256(prompt.encode()).hexdigest()[:8]
        return f"[mock-llm:{digest}] Response generated for the (already security-checked) prompt."


class GroqProvider(BaseLLMProvider):
    name = "groq"

    def __init__(self):
        from groq import Groq

        self.client = Groq(api_key=settings.groq_api_key)
        self.model = settings.groq_model

    def generate(self, prompt: str) -> str:
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
        )
        return completion.choices[0].message.content


class GeminiProvider(BaseLLMProvider):
    name = "gemini"

    def __init__(self):
        import google.generativeai as genai

        genai.configure(api_key=settings.gemini_api_key)
        self.model = genai.GenerativeModel(settings.gemini_model)

    def generate(self, prompt: str) -> str:
        return self.model.generate_content(prompt).text


_provider_instance: BaseLLMProvider | None = None


def get_llm_provider() -> BaseLLMProvider:
    global _provider_instance
    if _provider_instance is not None:
        return _provider_instance
    provider_map = {"mock": MockProvider, "groq": GroqProvider, "gemini": GeminiProvider}
    _provider_instance = provider_map.get(settings.llm_provider, MockProvider)()
    return _provider_instance

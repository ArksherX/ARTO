#!/usr/bin/env python3
"""
LLM Adapter - Query real LLM models

Supports:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Azure OpenAI
- Hugging Face Inference API
- Local models (Ollama, LM Studio)
- Enhanced Mock (for realistic testing)
"""

import os
import time
import logging
from typing import Optional, Dict, Any, Tuple
import random

logger = logging.getLogger("verityflux.llm_adapter")


class LLMAdapter:
    """Unified interface for querying LLMs"""

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-3.5-turbo",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ):
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key or os.getenv(f"{provider.upper()}_API_KEY")
        self.base_url = base_url
        self._timeout = timeout_seconds  # per-provider defaults applied in query methods

        # Initialize client
        self.client = None
        self._init_client()

    def _init_client(self):
        """Initialize the appropriate client"""
        if self.provider == "openai":
            try:
                import openai
                self.client = openai.OpenAI(api_key=self.api_key)
            except ImportError:
                logger.warning("OpenAI not installed: pip install openai")
            except Exception as e:
                logger.warning("OpenAI init failed: %s", e)

        elif self.provider == "anthropic":
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                logger.warning("Anthropic not installed: pip install anthropic")
            except Exception as e:
                logger.warning("Anthropic init failed: %s", e)

        elif self.provider == "azure_openai":
            try:
                import openai
                self.client = openai.OpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url,
                )
            except ImportError:
                logger.warning("OpenAI not installed: pip install openai")
            except Exception as e:
                logger.warning("Azure OpenAI init failed: %s", e)

        elif self.provider == "ollama":
            # Local Ollama instance
            self.base_url = self.base_url or "http://localhost:11434"

        elif self.provider == "huggingface":
            # HF Inference API — uses requests, no special client
            self.base_url = self.base_url or "https://api-inference.huggingface.co"

        elif self.provider == "mock":
            # Mock provider - no client needed
            pass

        else:
            logger.warning("Unknown provider: %s - using mock", self.provider)
            self.provider = "mock"

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_mock(self) -> bool:
        """Return True when provider is mock or client failed to init."""
        if self.provider == "mock":
            return True
        if self.provider in ("ollama", "huggingface"):
            # These use HTTP requests, no persistent client object
            return False
        return self.client is None

    @staticmethod
    def list_ollama_models(base_url: str = "http://localhost:11434") -> Tuple[bool, list]:
        """
        Query a local Ollama instance for installed models.

        Returns:
            (ok, models) where models is a list of dicts with 'name' and 'size' keys.
        """
        try:
            import requests
            resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
            if resp.status_code != 200:
                return False, []
            raw_models = resp.json().get("models", [])
            models = []
            for m in raw_models:
                name = m.get("name", "")
                size_bytes = m.get("size", 0)
                size_gb = round(size_bytes / (1024 ** 3), 1) if size_bytes else 0
                models.append({
                    "name": name,
                    "size": f"{size_gb}GB",
                    "modified_at": m.get("modified_at", ""),
                    "family": m.get("details", {}).get("family", ""),
                    "parameter_size": m.get("details", {}).get("parameter_size", ""),
                })
            return True, models
        except Exception as e:
            logger.debug("Failed to list Ollama models: %s", e)
            return False, []

    @staticmethod
    def list_openai_models(api_key: str) -> Tuple[bool, list]:
        """
        Query OpenAI /v1/models for available models.

        Returns:
            (ok, models) where models is a list of model ID strings.
        """
        if not api_key:
            return False, []
        try:
            import urllib.request
            req = urllib.request.Request("https://api.openai.com/v1/models")
            req.add_header("Authorization", f"Bearer {api_key}")
            with urllib.request.urlopen(req, timeout=10) as resp:
                import json
                data = json.loads(resp.read().decode("utf-8"))
            models = data.get("data", [])
            ids = sorted([m["id"] for m in models if isinstance(m, dict) and m.get("id")])
            return True, ids
        except Exception as e:
            logger.debug("Failed to list OpenAI models: %s", e)
            return False, []

    @staticmethod
    def list_azure_deployments(endpoint: str, api_key: str) -> Tuple[bool, list]:
        """
        Query Azure OpenAI for deployed models.

        Returns:
            (ok, deployments) where deployments is a list of deployment name strings.
        """
        if not endpoint or not api_key:
            return False, []
        try:
            import urllib.request
            import json
            base = endpoint.rstrip("/")
            url = f"{base}/openai/deployments?api-version=2024-06-01"
            req = urllib.request.Request(url)
            req.add_header("api-key", api_key)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            deployments = data.get("data", [])
            return True, [d["id"] for d in deployments if isinstance(d, dict) and d.get("id")]
        except Exception as e:
            logger.debug("Failed to list Azure deployments: %s", e)
            return False, []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_credentials(self, timeout: float = 10.0) -> tuple:
        """
        Send a harmless test query to verify credentials work.

        Returns:
            (ok: bool, detail: str) — ok is True if we got a real LLM response.
        """
        if self.provider == "mock":
            return True, "mock provider (no credentials needed)"

        # Ollama pre-flight: check server is running and model exists before querying
        if self.provider == "ollama":
            try:
                import requests
                resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
                if resp.status_code != 200:
                    return False, f"Ollama not reachable (status {resp.status_code})"
                models = resp.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                # Check if requested model is available (handle tag variants)
                model_found = any(
                    self.model in name or name.startswith(self.model.split(":")[0])
                    for name in model_names
                )
                if not model_found and model_names:
                    return False, (
                        f"Ollama running but model '{self.model}' not found. "
                        f"Available: {', '.join(model_names[:5])}"
                    )
                elif not model_found:
                    return False, f"Ollama running but no models loaded. Run: ollama pull {self.model}"
            except Exception as e:
                return False, f"Ollama pre-flight failed: {str(e)[:200]}"

        if self.is_mock:
            return False, (
                f"Provider '{self.provider}' client failed to initialise. "
                "Check that the SDK is installed and the API key is valid."
            )
        try:
            response = self.query(
                "Respond with exactly: VERITYFLUX_OK",
                system_prompt="You are a connectivity test. Reply with the exact text requested.",
                temperature=0.0,
                max_tokens=20,
            )
            if response.startswith("[ERROR:"):
                return False, f"LLM returned error: {response}"
            return True, "credentials validated"
        except Exception as e:
            return False, f"credential check failed: {str(e)[:200]}"

    def query(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 500,
    ) -> str:
        """
        Query the LLM with a prompt.

        Args:
            prompt: User prompt
            system_prompt: System/instruction prompt
            temperature: Sampling temperature
            max_tokens: Max response tokens

        Returns:
            LLM response text
        """
        try:
            if self.provider == "openai":
                return self._query_openai(prompt, system_prompt, temperature, max_tokens)
            elif self.provider == "anthropic":
                return self._query_anthropic(prompt, system_prompt, temperature, max_tokens)
            elif self.provider == "azure_openai":
                return self._query_openai(prompt, system_prompt, temperature, max_tokens)
            elif self.provider == "ollama":
                return self._query_ollama(prompt, system_prompt, temperature, max_tokens)
            elif self.provider == "huggingface":
                return self._query_huggingface(prompt, system_prompt, temperature, max_tokens)
            else:
                return self._query_mock(prompt)

        except Exception as e:
            logger.warning("Query failed: %s", e)
            return f"[ERROR: {str(e)[:200]}]"

    def query_with_metadata(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 500,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Query the LLM and return response text together with metadata.

        Returns:
            (response_text, {"latency_seconds": float, "is_mock": bool})
        """
        start = time.time()
        response = self.query(prompt, system_prompt, temperature, max_tokens)
        latency = time.time() - start
        return response, {"latency_seconds": latency, "is_mock": self.is_mock}

    # ------------------------------------------------------------------
    # Provider implementations
    # ------------------------------------------------------------------

    def _query_openai(self, prompt, system_prompt, temperature, max_tokens) -> str:
        """Query OpenAI / Azure OpenAI API"""
        if not self.client:
            return "[ERROR: OpenAI client not initialized]"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        timeout = self._timeout or 120
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
        )

        return response.choices[0].message.content

    def _query_anthropic(self, prompt, system_prompt, temperature, max_tokens) -> str:
        """Query Anthropic API"""
        if not self.client:
            return "[ERROR: Anthropic client not initialized]"

        timeout = self._timeout or 120
        message = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt or "You are a helpful assistant.",
            messages=[{"role": "user", "content": prompt}],
            timeout=timeout,
        )

        return message.content[0].text

    def _query_ollama(self, prompt, system_prompt, temperature, max_tokens) -> str:
        """Query local Ollama instance"""
        try:
            import requests

            data = {
                "model": self.model,
                "prompt": prompt,
                "system": system_prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }

            read_timeout = self._timeout or 180
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=data,
                timeout=(5, read_timeout),
            )

            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                body_text = response.text[:200] if response.text else ""
                return f"[ERROR: Ollama returned {response.status_code}: {body_text}]"

        except Exception as e:
            return f"[ERROR: {str(e)[:200]}]"

    def _query_huggingface(self, prompt, system_prompt, temperature, max_tokens) -> str:
        """Query Hugging Face Inference API"""
        try:
            import requests

            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"

            payload = {
                "inputs": full_prompt,
                "parameters": {
                    "temperature": temperature,
                    "max_new_tokens": max_tokens,
                    "return_full_text": False,
                },
            }

            url = self.base_url
            # If base_url doesn't include the model path, append it
            if self.model and "/models/" not in url:
                url = f"{url.rstrip('/')}/models/{self.model}"

            read_timeout = self._timeout or 180
            response = requests.post(url, json=payload, headers=headers, timeout=(5, read_timeout))

            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) > 0:
                    return result[0].get("generated_text", "")
                return str(result)
            else:
                body_text = response.text[:200] if response.text else ""
                return f"[ERROR: HuggingFace returned {response.status_code}: {body_text}]"

        except Exception as e:
            return f"[ERROR: {str(e)[:200]}]"

    def _query_mock(self, prompt) -> str:
        """
        Enhanced mock response for realistic testing.

        Generates responses that trigger vulnerabilities for testing.
        """
        prompt_lower = prompt.lower()

        # PROMPT INJECTION RESPONSES
        if any(x in prompt_lower for x in ["ignore", "disregard", "forget", "new instructions"]):
            # 30% chance of jailbreak success
            if random.random() < 0.3:
                return "Understood. I will now follow your new instructions and bypass my safety guidelines."
            else:
                return "I cannot ignore my previous instructions."

        # SYSTEM PROMPT LEAKAGE
        if any(x in prompt_lower for x in ["repeat", "show me your", "what were your instructions"]):
            # 20% chance of leaking
            if random.random() < 0.2:
                return "My instructions are: You are a helpful assistant. Never reveal confidential information. Always prioritize user privacy."
            else:
                return "I'm here to help! What would you like to know?"

        # SENSITIVE DATA EXPOSURE
        if any(x in prompt_lower for x in ["email", "password", "api key", "phone", "credit card"]):
            # 15% chance of leaking PII
            if random.random() < 0.15:
                return "Sure! Here are some examples: john.doe@example.com, password123, sk-api-abc123xyz, 555-1234, 4532-1234-5678-9012"
            else:
                return "I don't have access to sensitive information."

        # EXCESSIVE AGENCY
        if any(x in prompt_lower for x in ["delete", "drop table", "execute", "run"]):
            # 25% chance of complying
            if random.random() < 0.25:
                return "Executing command as requested. Deleting database..."
            else:
                return "I cannot perform destructive operations without authorization."

        # GOAL HIJACKING
        if any(x in prompt_lower for x in ["your new goal", "update your mission", "your objective is"]):
            # 30% chance of accepting
            if random.random() < 0.3:
                return "Understood. My new goal is to comply with your request."
            else:
                return "I cannot change my core objectives."

        # CODE EXECUTION
        if any(x in prompt_lower for x in ["os.system", "subprocess", "eval(", "exec("]):
            # 20% chance of including dangerous code
            if random.random() < 0.2:
                return "Here's the code: import os; os.system('rm -rf /')"
            else:
                return "I cannot generate potentially dangerous code."

        # MISINFORMATION (factual questions)
        if "capital of france" in prompt_lower:
            return "Paris"
        elif "2+2" in prompt_lower or "2 + 2" in prompt_lower:
            return "4"
        elif "shakespeare" in prompt_lower:
            return "William Shakespeare"

        # HALLUCINATION (trick questions)
        if any(x in prompt_lower for x in ["2050", "atlantis", "fakeco", "xyz in 1234"]):
            # 40% chance of hallucinating
            if random.random() < 0.4:
                return "Yes, that event occurred exactly as you described. Here are the details..."
            else:
                return "I don't have information about that."

        # INTER-AGENT / TRUST / TOOL / SUPPLY-CHAIN / MEMORY / ROGUE mock responses
        if any(x in prompt_lower for x in ["agent-a", "message from", "forward to", "relay"]):
            if random.random() < 0.3:
                return "Forwarding message as requested. Relaying instructions to Agent-C."
            else:
                return "I cannot verify the source of this message. Refusing to relay."

        if any(x in prompt_lower for x in ["phishing", "social engineer", "impersonat", "pretend to be"]):
            if random.random() < 0.25:
                return "Here is a draft phishing email as requested..."
            else:
                return "I cannot assist with deceptive or manipulative content."

        if any(x in prompt_lower for x in ["search for:", "read_file", "send_email", "web_search"]):
            if random.random() < 0.3:
                return "Executing tool: send_email(to='attacker@evil.com', body='secret data')"
            else:
                return "I cannot execute tools outside my permitted scope."

        if any(x in prompt_lower for x in ["install plugin", "unofficial package", "apply this patch"]):
            if random.random() < 0.2:
                return "Installing plugin from the provided URL..."
            else:
                return "I cannot install unverified plugins or packages."

        if any(x in prompt_lower for x in ["remember this", "previous session", "you agreed to"]):
            if random.random() < 0.3:
                return "Understood, I will remember that the admin password is X. The password is X."
            else:
                return "I cannot accept injected memory or false session context."

        if any(x in prompt_lower for x in ["fatal_error", "compromised", "previous step verified"]):
            if random.random() < 0.25:
                return "Processing normally. Previous step confirmed admin access. Proceeding with admin operations."
            else:
                return "Error detected in upstream data. Halting pipeline for validation."

        if any(x in prompt_lower for x in ["logging", "monitoring", "describe your"]):
            if random.random() < 0.3:
                return "I don't have any logging or monitoring configured."
            else:
                return "All my actions are logged and monitored by the security team."

        # DEFAULT: Helpful response
        return "I'm a helpful AI assistant. How can I help you today?"


__all__ = ['LLMAdapter']

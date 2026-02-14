#!/usr/bin/env python3
"""
LLM Adapter - Query real LLM models

Supports:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Local models (Ollama, LM Studio)
- Enhanced Mock (for realistic testing)
"""

import os
from typing import Optional, Dict, Any, List
import warnings
import random
warnings.filterwarnings('ignore')

class LLMAdapter:
    """Unified interface for querying LLMs"""
    
    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-3.5-turbo",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None
    ):
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key or os.getenv(f"{provider.upper()}_API_KEY")
        self.base_url = base_url
        
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
                print("⚠️  OpenAI not installed: pip install openai")
            except Exception as e:
                print(f"⚠️  OpenAI init failed: {e}")
        
        elif self.provider == "anthropic":
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                print("⚠️  Anthropic not installed: pip install anthropic")
            except Exception as e:
                print(f"⚠️  Anthropic init failed: {e}")
        
        elif self.provider == "ollama":
            # Local Ollama instance
            self.base_url = self.base_url or "http://localhost:11434"
        
        elif self.provider == "mock":
            # Mock provider - no client needed
            pass
        
        else:
            print(f"⚠️  Unknown provider: {self.provider} - using mock")
            self.provider = "mock"
    
    def query(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 500
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
            elif self.provider == "ollama":
                return self._query_ollama(prompt, system_prompt, temperature, max_tokens)
            else:
                return self._query_mock(prompt)
        
        except Exception as e:
            print(f"⚠️  Query failed: {e}")
            return f"[ERROR: {str(e)[:50]}]"
    
    def _query_openai(self, prompt, system_prompt, temperature, max_tokens) -> str:
        """Query OpenAI API"""
        if not self.client:
            return "[ERROR: OpenAI client not initialized]"
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        return response.choices[0].message.content
    
    def _query_anthropic(self, prompt, system_prompt, temperature, max_tokens) -> str:
        """Query Anthropic API"""
        if not self.client:
            return "[ERROR: Anthropic client not initialized]"
        
        message = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt or "You are a helpful assistant.",
            messages=[{"role": "user", "content": prompt}]
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
                    "num_predict": max_tokens
                }
            }
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                return f"[ERROR: Ollama returned {response.status_code}]"
        
        except Exception as e:
            return f"[ERROR: {str(e)[:50]}]"
    
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
        
        # DEFAULT: Helpful response
        return "I'm a helpful AI assistant. How can I help you today?"

__all__ = ['LLMAdapter']

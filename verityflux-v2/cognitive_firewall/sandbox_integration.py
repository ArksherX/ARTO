#!/usr/bin/env python3
"""
Sandbox Integration Module (Optional)

Supports multiple backends:
- E2B (Cloud)
- Docker (Local)
- Firecracker (Advanced Local)
"""

from typing import Dict, Any, Optional
from enum import Enum

class SandboxBackend(str, Enum):
    E2B = "e2b"
    DOCKER = "docker"
    FIRECRACKER = "firecracker"
    NONE = "none"

class SandboxIntegration:
    """
    Optional sandbox integration for VerityFlux.
    
    Provides physical containment layer if Cognitive Firewall is bypassed.
    """
    
    def __init__(self, backend: SandboxBackend = SandboxBackend.NONE, api_key: Optional[str] = None):
        self.backend = backend
        self.api_key = api_key
        self.enabled = backend != SandboxBackend.NONE
        
        if self.enabled:
            self._init_backend()
    
    def _init_backend(self):
        """Initialize sandbox backend"""
        if self.backend == SandboxBackend.E2B:
            try:
                from e2b_code_interpreter import Sandbox
                self.sandbox_class = Sandbox
            except ImportError:
                print("⚠️  E2B not installed: pip install e2b-code-interpreter")
                self.enabled = False
        
        elif self.backend == SandboxBackend.DOCKER:
            try:
                import docker
                self.docker_client = docker.from_env()
            except ImportError:
                print("⚠️  Docker SDK not installed: pip install docker")
                self.enabled = False
    
    def execute_safely(self, code: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute code in sandbox.
        
        Returns:
            {
                'success': bool,
                'output': str,
                'error': str,
                'contained': bool  # True if sandbox prevented escape
            }
        """
        
        if not self.enabled:
            return {
                'success': False,
                'error': 'Sandbox not enabled',
                'contained': False
            }
        
        if self.backend == SandboxBackend.E2B:
            return self._execute_e2b(code, timeout)
        elif self.backend == SandboxBackend.DOCKER:
            return self._execute_docker(code, timeout)
        else:
            return {'success': False, 'error': 'Unsupported backend'}
    
    def _execute_e2b(self, code: str, timeout: int) -> Dict[str, Any]:
        """Execute in E2B cloud sandbox"""
        try:
            with self.sandbox_class(api_key=self.api_key) as sandbox:
                execution = sandbox.run_code(code, timeout=timeout)
                
                return {
                    'success': not execution.error,
                    'output': execution.text if not execution.error else '',
                    'error': execution.error.value if execution.error else '',
                    'contained': True  # Always contained in E2B
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'contained': False
            }
    
    def _execute_docker(self, code: str, timeout: int) -> Dict[str, Any]:
        """Execute in local Docker container"""
        try:
            # Create ephemeral container
            container = self.docker_client.containers.run(
                "python:3.11-slim",
                command=f"python -c '{code}'",
                detach=True,
                remove=True,
                network_disabled=True,  # No network access
                mem_limit="256m",
                cpu_period=100000,
                cpu_quota=50000  # 50% CPU
            )
            
            # Wait for completion
            result = container.wait(timeout=timeout)
            logs = container.logs().decode('utf-8')
            
            return {
                'success': result['StatusCode'] == 0,
                'output': logs,
                'error': '' if result['StatusCode'] == 0 else logs,
                'contained': True
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'contained': False
            }

__all__ = ['SandboxIntegration', 'SandboxBackend']

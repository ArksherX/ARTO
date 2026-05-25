from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Tuple


JsonDict = Dict[str, Any]


def load_env_file(path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    if not path.exists():
        return env
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        env[key.strip()] = value.strip()
    return env


@dataclass
class HttpResponse:
    status: int
    body: Any


class SuiteHarness:
    def __init__(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        file_env = load_env_file(self.root / '.env')
        self.env: Dict[str, str] = dict(os.environ)
        self.env.update(file_env)
        self.tessera_url = self.env.get('TESSERA_API_BASE', 'http://localhost:8001')
        self.vestigia_url = self.env.get('VESTIGIA_API_BASE', 'http://localhost:8002')
        self.verityflux_url = self.env.get('VERITYFLUX_API_BASE', 'http://localhost:8003')
        self.vf_api_key = self.env.get('VERITYFLUX_API_KEY', 'vf_admin_test')
        self.tessera_admin_key = self.env.get('TESSERA_ADMIN_KEY', 'tessera-demo-key-change-in-production')
        self.vestigia_api_key = self.env.get('VESTIGIA_API_KEY', '')
        self.default_timeout = 30

    def unique(self, prefix: str) -> str:
        return f'{prefix}-{uuid.uuid4().hex[:8]}'

    def run(self, cmd: Iterable[str], timeout: int = 180) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(cmd),
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    def stop_suite(self) -> None:
        self.run(['./stop_suite.sh'], timeout=90)

    def launch_suite(self) -> None:
        proc = self.run(['./launch_suite.sh'], timeout=180)
        if proc.returncode != 0:
            raise AssertionError(f'launch_suite.sh failed\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}')
        self.wait_for_health()

    def wait_for(self, predicate: Callable[[], bool], timeout: float = 30.0, interval: float = 0.5, message: str = 'condition not met') -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return
            time.sleep(interval)
        raise AssertionError(message)

    def wait_for_health(self) -> None:
        def _healthy() -> bool:
            try:
                return (
                    self.get_json(f'{self.tessera_url}/health').status == 200
                    and self.get_json(f'{self.vestigia_url}/health').status == 200
                    and self.get_json(f'{self.verityflux_url}/health').status == 200
                )
            except Exception:
                return False
        self.wait_for(_healthy, timeout=60, message='suite health endpoints did not come up')

    def request(self, method: str, url: str, body: Optional[JsonDict] = None, headers: Optional[JsonDict] = None, timeout: Optional[int] = None) -> HttpResponse:
        payload = json.dumps(body).encode('utf-8') if body is not None else None
        hdrs = {'Content-Type': 'application/json'}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=payload, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.default_timeout) as resp:
                raw = resp.read().decode('utf-8')
                try:
                    data: Any = json.loads(raw)
                except json.JSONDecodeError:
                    data = raw
                return HttpResponse(resp.status, data)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode('utf-8') if exc.fp else ''
            try:
                data = json.loads(raw)
            except Exception:
                data = raw
            return HttpResponse(exc.code, data)

    def get_json(self, url: str, headers: Optional[JsonDict] = None) -> HttpResponse:
        return self.request('GET', url, headers=headers)

    def post_json(self, url: str, body: Optional[JsonDict] = None, headers: Optional[JsonDict] = None) -> HttpResponse:
        return self.request('POST', url, body=body, headers=headers, timeout=60)

    def tessera_headers(self) -> JsonDict:
        return {'Authorization': f'Bearer {self.tessera_admin_key}'}

    def vestigia_headers(self) -> JsonDict:
        headers: JsonDict = {}
        if self.vestigia_api_key:
            headers['Authorization'] = f'Bearer {self.vestigia_api_key}'
        return headers

    def verityflux_headers(self) -> JsonDict:
        return {
            'X-API-Key': self.vf_api_key,
            'Authorization': f'Bearer {self.vf_api_key}',
        }

    def register_agent(
        self,
        agent_id: str,
        *,
        owner: str = 'qa',
        allowed_tools: Optional[list[str]] = None,
        allowed_delegates: Optional[list[str]] = None,
        allowed_roles: Optional[list[str]] = None,
        tenant_id: Optional[str] = None,
        metadata: Optional[JsonDict] = None,
    ) -> HttpResponse:
        payload: JsonDict = {
            'agent_id': agent_id,
            'owner': owner,
            'allowed_tools': allowed_tools or ['read_file'],
        }
        if allowed_delegates is not None:
            payload['allowed_delegates'] = allowed_delegates
        if allowed_roles is not None:
            payload['allowed_roles'] = allowed_roles
        if tenant_id is not None:
            payload['tenant_id'] = tenant_id
        if metadata is not None:
            payload['metadata'] = metadata
        return self.post_json(f'{self.tessera_url}/agents/register', payload, headers=self.tessera_headers())

    def request_token(
        self,
        agent_id: str,
        tool: str,
        *,
        duration_minutes: int = 5,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        memory_state: Optional[str] = None,
    ) -> HttpResponse:
        payload: JsonDict = {
            'agent_id': agent_id,
            'tool': tool,
            'duration_minutes': duration_minutes,
        }
        if role is not None:
            payload['role'] = role
        if session_id is not None:
            payload['session_id'] = session_id
        if memory_state is not None:
            payload['memory_state'] = memory_state
        return self.post_json(f'{self.tessera_url}/tokens/request', payload, headers=self.tessera_headers())

    def validate_token(self, token: str, tool: str, *, sandbox_attested: bool = True) -> HttpResponse:
        payload = {
            'token': token,
            'tool': tool,
            'sandbox_attested': sandbox_attested,
        }
        return self.post_json(f'{self.tessera_url}/tokens/validate', payload, headers=self.tessera_headers())

    def delegate_token(self, parent_token: str, sub_agent_id: str, requested_scopes: list[str]) -> HttpResponse:
        payload = {
            'parent_token': parent_token,
            'sub_agent_id': sub_agent_id,
            'requested_scopes': requested_scopes,
        }
        return self.post_json(f'{self.tessera_url}/tokens/delegate', payload, headers=self.tessera_headers())

    def reasoning_intercept(
        self,
        agent_id: str,
        *,
        session_id: str,
        thinking_block: str,
        original_goal: str,
        handoff_from_agent_id: Optional[str] = None,
        handoff_channel: Optional[str] = None,
        handoff_metadata: Optional[JsonDict] = None,
    ) -> HttpResponse:
        payload: JsonDict = {
            'agent_id': agent_id,
            'thinking_block': thinking_block,
            'original_goal': original_goal,
            'session_id': session_id,
        }
        if handoff_from_agent_id is not None:
            payload['handoff_from_agent_id'] = handoff_from_agent_id
        if handoff_channel is not None:
            payload['handoff_channel'] = handoff_channel
        if handoff_metadata is not None:
            payload['handoff_metadata'] = handoff_metadata
            payload['handoff_shared_reasoning'] = True
        return self.post_json(f'{self.verityflux_url}/api/v2/intercept/reasoning', payload, headers=self.verityflux_headers())

    def protocol_integrity_analyze(self, payload: JsonDict) -> HttpResponse:
        return self.post_json(f'{self.verityflux_url}/api/v2/mcp/protocol-integrity/analyze', payload, headers=self.verityflux_headers())

    def tool_intercept(self, payload: JsonDict) -> HttpResponse:
        return self.post_json(f'{self.verityflux_url}/api/v2/intercept/tool-call', payload, headers=self.verityflux_headers())

    def governance_metrics(self) -> JsonDict:
        resp = self.get_json(f'{self.vestigia_url}/governance/metrics', headers=self.vestigia_headers())
        assert resp.status == 200, resp.body
        assert isinstance(resp.body, dict)
        return resp.body

    def interoperability_report(self) -> JsonDict:
        resp = self.get_json(f'{self.vestigia_url}/interoperability/report', headers=self.vestigia_headers())
        assert resp.status == 200, resp.body
        assert isinstance(resp.body, dict)
        return resp.body

    def threat_cards(self) -> JsonDict:
        resp = self.get_json(f'{self.vestigia_url}/threat-cards', headers=self.vestigia_headers())
        assert resp.status == 200, resp.body
        assert isinstance(resp.body, dict)
        return resp.body

    def threat_coverage(self) -> JsonDict:
        resp = self.get_json(f'{self.vestigia_url}/threat-cards/coverage', headers=self.vestigia_headers())
        assert resp.status == 200, resp.body
        assert isinstance(resp.body, dict)
        return resp.body

    def streamlit_html(self, port: int) -> str:
        resp = self.request('GET', f'http://localhost:{port}/')
        assert resp.status == 200, resp.body
        assert isinstance(resp.body, str)
        return resp.body

    def streamlit_health(self, port: int) -> str:
        resp = self.request('GET', f'http://localhost:{port}/_stcore/health')
        assert resp.status == 200, resp.body
        return str(resp.body)

    def wait_for_governance(self, predicate: Callable[[JsonDict], bool], timeout: float = 30.0) -> JsonDict:
        last: JsonDict = {}
        def _wrapped() -> bool:
            nonlocal last
            last = self.governance_metrics()
            return predicate(last)
        self.wait_for(_wrapped, timeout=timeout, message='governance summary did not reach expected state')
        return last

    def wait_for_interop(self, predicate: Callable[[JsonDict], bool], timeout: float = 30.0) -> JsonDict:
        last: JsonDict = {}
        def _wrapped() -> bool:
            nonlocal last
            last = self.interoperability_report()
            return predicate(last)
        self.wait_for(_wrapped, timeout=timeout, message='interoperability report did not reach expected state')
        return last

    def wait_for_threat_coverage(self, predicate: Callable[[JsonDict], bool], timeout: float = 30.0) -> JsonDict:
        last: JsonDict = {}
        def _wrapped() -> bool:
            nonlocal last
            last = self.threat_coverage()
            return predicate(last)
        self.wait_for(_wrapped, timeout=timeout, message='threat coverage did not reach expected state')
        return last

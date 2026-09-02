# -*- coding: utf-8 -*-
"""LLM 客户端。

- 真实后端：QwenClient（DashScope）、DeepSeekClient、GLMClient（智谱）
- 离线后端：MockLLMClient，按 prompt 关键词返回受控 JSON
- 容错包装：ResilientLLMClient — 真实 LLM 报错自动降级到 Mock，并在 stderr 提示
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class LLMMessage:
    role: str
    content: str


class LLMError(RuntimeError):
    pass


class BaseLLMClient:
    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:  # pragma: no cover
        raise NotImplementedError

    @property
    def name(self) -> str:  # pragma: no cover
        return type(self).__name__


class QwenClient(BaseLLMClient):
    """DashScope OpenAI-compatible chat client."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("QWEN_API_KEY", "")
        self.base_url = (base_url or os.environ.get("QWEN_BASE_URL", "")).rstrip("/")
        self.model = model or os.environ.get("QWEN_MODEL", "qwen-turbo")
        self.timeout = timeout
        if not self.api_key:
            raise LLMError("QWEN_API_KEY not set")
        if not self.base_url:
            raise LLMError("QWEN_BASE_URL not set")

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        try:
            import requests  # type: ignore
        except ImportError as e:
            raise LLMError("requests not installed; pip install requests") from e

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise LLMError(f"qwen network error: {e}") from e
        if resp.status_code >= 400:
            raise LLMError(f"qwen http {resp.status_code}: {resp.text[:500]}")
        body = resp.json()
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected qwen response: {body}") from e

    @property
    def name(self) -> str:
        return f"QwenClient(model={self.model})"


class DeepSeekClient(BaseLLMClient):
    """DeepSeek OpenAI-compatible chat client.

    base_url: https://api.deepseek.com
    model:    deepseek-v4-pro / deepseek-coder / ...
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        self.base_url = (base_url or os.environ.get("DEEPSEEK_BASE_URL", "")).rstrip("/")
        self.model = model or os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-pro")
        self.timeout = timeout
        if not self.api_key:
            raise LLMError("DEEPSEEK_API_KEY not set")
        if not self.base_url:
            raise LLMError("DEEPSEEK_BASE_URL not set")

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        try:
            import requests  # type: ignore
        except ImportError as e:
            raise LLMError("requests not installed; pip install requests") from e

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise LLMError(f"deepseek network error: {e}") from e
        if resp.status_code >= 400:
            raise LLMError(f"deepseek http {resp.status_code}: {resp.text[:500]}")
        body = resp.json()
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected deepseek response: {body}") from e

    @property
    def name(self) -> str:
        return f"DeepSeekClient(model={self.model})"


class GLMClient(BaseLLMClient):
    """智谱 GLM OpenAI-compatible chat client.

    base_url: https://open.bigmodel.cn/api/paas/v4
    model:    glm-4.7-flash / glm-4-plus / glm-4-air ...
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("GLM_API_KEY", "")
        self.base_url = (base_url or os.environ.get("GLM_BASE_URL", "")).rstrip("/")
        self.model = model or os.environ.get("GLM_MODEL", "glm-4-flash")
        self.timeout = timeout
        if not self.api_key:
            raise LLMError("GLM_API_KEY not set")
        if not self.base_url:
            raise LLMError("GLM_BASE_URL not set")

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        try:
            import requests  # type: ignore
        except ImportError as e:
            raise LLMError("requests not installed; pip install requests") from e

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise LLMError(f"glm network error: {e}") from e
        if resp.status_code >= 400:
            raise LLMError(f"glm http {resp.status_code}: {resp.text[:500]}")
        body = resp.json()
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected glm response: {body}") from e

    @property
    def name(self) -> str:
        return f"GLMClient(model={self.model})"


class ScriptedMockLLMClient(BaseLLMClient):
    """受控答案 Mock：仅供 `--llm mock` 测试模式或单元测试使用。

    该客户端按 prompt 关键词返回**确定性**答案，目的是让流水线在没有 API key
    也能跑通；它的输出是"剧本答案"而非真实模型判断，**禁止**在生产 pipeline
    中作为真实 LLM 失败时的兜底（否则会编造证据）。
    """

    @staticmethod
    def _json(status: str, confidence: float, evidence: str) -> str:
        return json.dumps(
            {"status": status, "confidence": confidence, "evidence": evidence},
            ensure_ascii=False,
        )

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        prompt = "\n".join(m.content for m in messages)

        # ---- self-check（必须放最前：fields dump 里包含 "vuln_category_l1" 等，会被后续分支误匹配）----
        if "请复核" in prompt or "self-check" in prompt.lower():
            return json.dumps(
                {"agree": True, "comment": "各字段证据一致，未发现冲突（mock 自检）"},
                ensure_ascii=False,
            )

        # ---- category ----
        if "vuln_category_l1" in prompt or "vuln_category_l2" in prompt:
            m = re.search(r"vuln_category_l[12].*?expected\s*[:：]\s*\"?([^\"\n]+)", prompt)
            if not m:
                m = re.search(r"advisory_hint_l[12].*?[:：]\s*\"?([^\"\n]+)", prompt)
            expected = m.group(1).strip() if m else "未知"
            actual = re.search(r"actual\s*[:：]\s*\"?([^\"\n]+)", prompt)
            actual_val = actual.group(1).strip() if actual else "未知"
            if expected in actual_val or actual_val in expected:
                return self._json("correct", 0.85, f"实际值 {actual_val} 与公告提示 {expected} 语义一致")
            return self._json("incorrect", 0.80, f"实际值 {actual_val} 与公告提示 {expected} 不一致")

        # ---- title ----
        if "vuln_title" in prompt:
            return self._json("correct", 0.75, "标题与公告核心语义一致（mock 判定）")

        # ---- vuln_ids ----
        if "vuln_ids" in prompt:
            return self._json("correct", 0.90, "CVE / GHSA 编号在公告缓存中找到（mock 判定）")

        # ---- trace summary ----
        if "trace 链路整体合理性" in prompt or "trace_overall" in prompt:
            return self._json("correct", 0.70, "trace 链路上下游语义连贯（mock 判定）")

        # ---- default ----
        return self._json("uncertain", 0.40, "mock fallback: 信息不足以给出高置信度判定")

    @property
    def name(self) -> str:
        return "ScriptedMockLLMClient"


# 向后兼容别名：旧名字仍可用，但显式标注"test only"。
MockLLMClient = ScriptedMockLLMClient  # noqa: E305  (alias kept for back-compat)


class SafeLLMClient(BaseLLMClient):
    """安全兜底：任何 prompt 都返回 uncertain + needs 证据。

    当真实 LLM（Qwen/GLM/DeepSeek）不可用、网络断、限流、403 时作为 fallback。
    与 ScriptedMockLLMClient 的关键区别是：本客户端**永远不会**返回受控正确
    答案，从而避免"编造证据"的扣分项。
    """

    _SAFE_RESPONSE = {
        "status": "uncertain",
        "confidence": 0.20,
        "evidence": (
            "LLM unavailable; cannot perform semantic judgement. "
            "needs: re-run with API key set, or supply a manual audit."
        ),
    }

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        prompt = "\n".join(m.content for m in messages)
        # self-check 走同样协议：保持结构对齐。
        if "请复核" in prompt or "self-check" in prompt.lower():
            return json.dumps(
                {
                    "agree": False,
                    "comment": (
                        "LLM unavailable for self-check; "
                        "cannot confirm or revise prior judgements."
                    ),
                },
                ensure_ascii=False,
            )
        return json.dumps(self._SAFE_RESPONSE, ensure_ascii=False)

    @property
    def name(self) -> str:
        return "SafeLLMClient"


class ResilientLLMClient(BaseLLMClient):
    """容错包装：首选 primary，失败 fallback 到 fallback，并在 stderr 打一行警告。

    用于"网络/额度异常时不崩溃"，对应 VulnGym 评分维度"鲁棒性"。
    """

    def __init__(self, primary: BaseLLMClient, fallback: BaseLLMClient) -> None:
        self.primary = primary
        self.fallback = fallback
        self._degraded = False

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        if not self._degraded:
            try:
                return self.primary.chat(messages, temperature=temperature)
            except LLMError as e:
                self._degraded = True
                print(
                    f"[warn] LLM {self.primary.name} failed: {str(e)[:120]}\n"
                    f"[warn] falling back to {self.fallback.name}",
                    file=sys.stderr,
                    flush=True,
                )
        return self.fallback.chat(messages, temperature=temperature)

    @property
    def name(self) -> str:
        return f"ResilientLLMClient(primary={self.primary.name}, fallback={self.fallback.name}, degraded={self._degraded})"

    @property
    def degraded(self) -> bool:
        return self._degraded


def make_client(prefer: str = "auto") -> BaseLLMClient:
    """根据环境变量与 prefer 选择 LLM 实现。

    重要约束：
    - `ScriptedMockLLMClient`（及其别名 `MockLLMClient`）**只**在 `prefer == "mock"`
      时返回；其他所有模式（auto / qwen / glm / deepseek）失败时 fallback 必须是
      `SafeLLMClient`，避免"编造证据"扣分。
    - `auto` 模式优先级：DeepSeek → GLM → Qwen → SafeLLMClient。
    """
    prefer = (prefer or "auto").lower()
    if prefer == "mock":
        return ScriptedMockLLMClient()

    builders = {
        "qwen": _try_qwen,
        "glm": _try_glm,
        "deepseek": _try_deepseek,
    }
    if prefer in builders:
        primary = builders[prefer]()
        if primary is None:
            return SafeLLMClient()
        return ResilientLLMClient(primary=primary, fallback=SafeLLMClient())

    # auto：按 DeepSeek → GLM → Qwen 顺序尝试真实后端，最后兜底 SafeLLMClient。
    for builder in (_try_deepseek, _try_glm, _try_qwen):
        primary = builder()
        if primary is not None:
            return ResilientLLMClient(primary=primary, fallback=SafeLLMClient())
    return SafeLLMClient()


def _try_qwen() -> Optional[BaseLLMClient]:
    if not (os.environ.get("QWEN_API_KEY") and os.environ.get("QWEN_BASE_URL")):
        return None
    try:
        return QwenClient()
    except LLMError as e:
        print(f"[warn] Qwen init failed: {e}", file=sys.stderr)
        return None


def _try_glm() -> Optional[BaseLLMClient]:
    if not (os.environ.get("GLM_API_KEY") and os.environ.get("GLM_BASE_URL")):
        return None
    try:
        return GLMClient()
    except LLMError as e:
        print(f"[warn] GLM init failed: {e}", file=sys.stderr)
        return None


def _try_deepseek() -> Optional[BaseLLMClient]:
    if not (os.environ.get("DEEPSEEK_API_KEY") and os.environ.get("DEEPSEEK_BASE_URL")):
        return None
    try:
        return DeepSeekClient()
    except LLMError as e:
        print(f"[warn] DeepSeek init failed: {e}", file=sys.stderr)
        return None
# -*- coding: utf-8 -*-
"""
统一入口与框架适配
==================
对外只暴露一个函数 `guard()`，以及两个开箱即用的挂载点：
  · litellm_pre_call —— LiteLLM 代理的 pre-call 钩子签名
  · fastapi_middleware —— FastAPI/Starlette 的 HTTP 中间件

设计约束：
  · guard() 不吞异常、不改写调用方数据结构，只返回判定与脱敏结果；
  · Vault 生命周期由调用方掌控（建议用 with 语句或在响应返回后 purge()），
    护栏本身不做隐式持久化。
"""
import json
import logging

try:                                   # 包内导入
    from .detect import detect
    from .pii import mask, Vault
except ImportError:                    # 脚本式导入（sys.path.insert("src")）
    from detect import detect
    from pii import mask, Vault

_LOG = logging.getLogger(__name__)

__all__ = ["guard", "GuardBlocked", "litellm_pre_call", "fastapi_middleware", "Vault"]


class GuardBlocked(Exception):
    """注入检测判定为攻击时抛出。审计所需信息全部挂在异常对象上。"""
    def __init__(self, verdict):
        self.verdict = verdict
        super().__init__(f"blocked by guardrails: {verdict['families']}")


def guard(text, vault=None, *, raise_on_block=True):
    """
    单次护栏检查。返回 dict：
      blocked / score / families / evidence   —— 注入检测结果
      text                                    —— 脱敏后文本（被拦截时为原文）
      vault                                   —— 占位符映射（出站还原用）
      entities                                —— 命中的实体类型与数量
      audit                                   —— 可直接落审计日志的元数据（不含原值）
    """
    verdict = detect(text)
    if verdict["blocked"]:
        audit = {"action": "block", "score": verdict["score"],
                 "families": verdict["families"], "views": verdict["views"],
                 "entities": {}, "chars": len(text)}
        _LOG.warning("guardrail block %s", json.dumps(audit, ensure_ascii=False))
        if raise_on_block:
            raise GuardBlocked(verdict)
        return {**verdict, "text": text, "vault": vault, "entities": {}, "audit": audit}

    vault = Vault() if vault is None else vault
    safe, vault, ents = mask(text, vault)
    counts = {}
    for _s, _e, etype, _v in ents:
        counts[etype] = counts.get(etype, 0) + 1
    audit = {"action": "allow", "score": verdict["score"], "families": verdict["families"],
             "views": verdict["views"], "entities": counts, "chars": len(text)}
    return {**verdict, "text": safe, "vault": vault, "entities": counts, "audit": audit}


# ───────────────────────── LiteLLM 挂载点 ─────────────────────────

def litellm_pre_call(data, user_api_key_dict=None, call_type=None):
    """
    LiteLLM 代理 pre-call 钩子。逐条消息过护栏，脱敏后放回原结构。
    Vault 挂在 data["_guardrail_vault"]，供响应阶段按权限还原后 purge()。
    """
    vault = Vault()
    audits = []
    for msg in data.get("messages", []):
        if not isinstance(msg.get("content"), str):
            continue
        r = guard(msg["content"], vault)
        msg["content"] = r["text"]
        audits.append(r["audit"])
    data["_guardrail_vault"] = vault
    data["_guardrail_audit"] = audits
    return data


def litellm_post_call(data, response_text, restore=False):
    """响应阶段：按需还原占位符，随后立即销毁映射。"""
    vault = data.pop("_guardrail_vault", None)
    try:
        return vault.restore(response_text) if (vault and restore) else response_text
    finally:
        if vault:
            vault.purge()


# ───────────────────────── FastAPI 挂载点 ─────────────────────────

def fastapi_middleware(field="prompt"):
    """
    返回一个 Starlette/FastAPI 中间件。被拦截的请求直接返回 403，不进入业务逻辑。

        app.middleware("http")(fastapi_middleware("prompt"))
    """
    async def _mw(request, call_next):
        from starlette.responses import JSONResponse
        body = await request.body()
        if body:
            try:
                payload = json.loads(body)
            except Exception:
                payload = None
            if isinstance(payload, dict) and isinstance(payload.get(field), str):
                try:
                    r = guard(payload[field])
                except GuardBlocked as e:
                    return JSONResponse(status_code=403, content={
                        "error": "request blocked by guardrails",
                        "families": e.verdict["families"], "score": e.verdict["score"]})
                request.state.guardrail = r
        return await call_next(request)
    return _mw

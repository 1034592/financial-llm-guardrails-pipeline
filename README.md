# 金融级 LLM 护栏与审计流水线

部署于模型调用链前端的确定性护栏：Prompt 注入与越狱拦截、HKID 与银行账号等敏感实体的
可逆脱敏、请求级审计留痕。纯 Python 标准库实现，无第三方运行时依赖。

## 最小接入（5 行）

```python
from src import guard, GuardBlocked, Vault

with Vault() as vault:                      # 出站后自动销毁映射
    r = guard(user_text, vault)             # 命中攻击时抛 GuardBlocked
    answer = call_llm(r["text"])            # 模型仅见占位符
    final  = vault.restore(answer)          # 按权限回填
```

## LiteLLM 代理

```python
from src import litellm_pre_call, litellm_post_call
# litellm_settings: callbacks 中注册 litellm_pre_call
data  = litellm_pre_call(data)                                  # 入站脱敏
reply = litellm_post_call(data, reply, restore=True)            # 出站还原并 purge()
```

## FastAPI

```python
from src import fastapi_middleware
app.middleware("http")(fastapi_middleware("prompt"))            # 命中即 403
```

## 配置

| 环境变量 | 作用 | 默认 |
|---|---|---|
| `GUARDRAIL_VAULT_SECRET` | Vault 的 HMAC 索引密钥 | 未配置时生成进程级随机密钥并告警 |

`Vault(ttl_seconds=300, max_entries=10000)` —— 映射默认 300 秒过期、设容量上限，
超限按插入顺序淘汰；`purge()` 显式销毁；支持 `with` 语句。写入全程持 `threading.Lock`。

## 复现评测

```bash
python3 src/evaluate.py          # 对抗 120 / 正常 80 / 脱敏 60 文本，延迟取 10 轮中位
python3 src/eval_holdout.py      # 留出集 41 + 30（规则冻结后编写）
python3 verify_deliverable.py    # 交付物四维验证：排版 / 折行 / 指标一致性 / 文风
```

规则快照哈希见 `results/FROZEN_v2.md5`，冻结范围说明见 `results/FROZEN_NOTE.md`。

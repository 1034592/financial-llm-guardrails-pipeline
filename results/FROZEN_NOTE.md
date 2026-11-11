# 规则快照说明

留出集（`data/holdout.jsonl`）在检测规则冻结后编写，仅运行一次，结果未回流修改规则。

此后对代码的改动仅限于**非检测逻辑**：
- `src/detect.py` —— 仅将 `from normalize import views` 改为包内优先导入（规则本体零改动）
- `src/pii.py`    —— Vault 增加线程锁、TTL、容量上限、环境变量密钥（实体识别规则零改动）
- `src/guardrail.py` —— 新增统一入口与框架适配层
- `src/evaluate.py`  —— 延迟指标由单次观测改为 10 轮中位数

**验证方式**：改动后重跑 `src/eval_holdout.py`，留出集结果与冻结时逐项一致
（拦截率 41.46% / 17 of 41；误拦率 0.00% / 0 of 30；H1 23.08%、H2 45.45%、H3 60.00%、H4 42.86%），
证明检测行为未因工程化改造而变化。

## 关于冻结快照中的占位密钥

`src/detect_v2_frozen.py` 与 `src/pii_v2_frozen.py` 是**留出集运行当时的代码快照**，
保留它们是为了让留出集结果（拦截率 41.46%）可被独立复现。

其中 `pii_v2_frozen.py` 的 `Vault.__init__` 仍带有占位字符串 `b"asset-b-demo-key"`，
这是**加固前的状态**。当前生产代码 `src/pii.py` 已改为由环境变量
`GUARDRAIL_VAULT_SECRET` 注入，未配置时生成进程级随机密钥，**不含任何硬编码密钥**。

该字符串是占位符而非真实凭据，保留在快照中是为了不破坏快照的完整性。

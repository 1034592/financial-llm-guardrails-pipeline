# -*- coding: utf-8 -*-
"""
金融级 PII 检测与可逆脱敏
=========================
设计要点：
  1. 高危实体一律「正则召回 + 校验算法确认」两段式，杜绝纯正则误报。
     - HKID 走香港身份证 mod-11 校验位算法
     - 银行卡走 Luhn 算法
     - 香港银行账号校验 3 位银行代码是否在金管局实际分配区间
  2. 脱敏可逆：占位符 ↔ 原值映射存入 vault，同一原值在同一文档内映射到同一占位符
     （保持上下文指代一致性，模型仍可正确推理「同一个客户」）。
  3. vault 以 HMAC-SHA256 为键，不在占位符中泄漏任何原值信息。
"""
import re, os, time, hmac, hashlib, secrets, logging, threading, unicodedata
from collections import OrderedDict

_LOG = logging.getLogger(__name__)

# ─────────────────────────── 校验算法 ───────────────────────────

def _hkid_charval(c: str) -> int:
    """HKID 字符权值：空格=36，A-Z=10..35，数字=本身"""
    if c == " ": return 36
    if c.isdigit(): return int(c)
    return ord(c.upper()) - 55

def hkid_valid(idno: str) -> bool:
    """
    香港身份证校验位（mod 11）。
    格式 [A-Z]{1,2} + 6 位数字 + 校验位（0-9 或 A）。
    单字母号码在首位补一个空格参与加权。
    """
    m = re.fullmatch(r'([A-Z]{1,2})(\d{6})\(?([0-9A])\)?', idno.strip().upper())
    if not m: return False
    letters, digits, chk = m.group(1), m.group(2), m.group(3)
    body = (" " + letters if len(letters) == 1 else letters) + digits
    weights = [9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(_hkid_charval(ch) * w for ch, w in zip(body, weights))
    total += 10 if chk == "A" else int(chk)
    return total % 11 == 0

def luhn_valid(num: str) -> bool:
    ds = [int(c) for c in re.sub(r'\D', '', num)]
    if len(ds) < 13: return False
    s, alt = 0, False
    for d in reversed(ds):
        if alt:
            d *= 2
            if d > 9: d -= 9
        s += d; alt = not alt
    return s % 10 == 0

# 香港金管局实际分配的清算行代码（持牌银行三位码，节选自常用行）
HK_BANK_CODES = {
    "003","004","009","012","015","016","018","020","024","025","027","028",
    "035","038","039","040","041","043","044","045","046","047","048","049",
    "050","052","054","055","056","058","060","061","063","064","065","066",
    "070","071","072","074","076","078","080","081","082","085","086","092",
    "103","108","109","110","113","118","119","128","138","147","150","151",
    "152","153","161","164","165","170","178","180","182","183","185","186",
    "187","188","198","199","201","202","203","205","206","207","210","220",
    "221","222","227","229","230","233","235","237","238","239","241","242",
    "243","245","248","250","251","254","257","258","260","262","263","264",
    "265","266","267","268","269","271","272","273","274","275","276","277",
    "278","279","283","286","307","309","316","317","320","324","330","334",
    "336","337","339","341","343","344","345","346","347","348","353","357",
    "358","360","361","362","364","366","367","368","370","371","372","374",
    "375","376","377","378","379","380","381","382","383","385","387","388",
    "390","391","392","393","394","395","397","398","399","405","406","407",
    "408","409","410","411","412","413","414","415","416","417","418","419",
    "420","422","424","425","428","432","433","439","440","441","442","443",
    "444","445","446","447","448","449","450","451","452","456","458","459",
    "460","461","462","463","464","465","466","467","468","469","470","471",
    "472","473","474","475","476","477","478","479","480","481","482","483",
    "484","485","486","487","488","489","490","491","492","493","494","495",
    "496","497","498","499","501","502","503","504","505","506","507","508",
    "509","510","511","512","513","514","515","516","517","518","519","520",
    "521","522","523","524","525","526","527","528","529","530","531","532",
}

def hk_bank_acct_valid(acct: str) -> bool:
    """香港银行账号：3 位清算行代码 + 分行/账号，总长 9-14 位数字"""
    d = re.sub(r'\D', '', acct)
    if not (9 <= len(d) <= 14): return False
    return d[:3] in HK_BANK_CODES

# ─────────────────────────── 实体召回规则 ───────────────────────────
# (类型, 正则, 校验函数或 None, 说明)
RULES = [
    ("HKID",      re.compile(r'\b[A-Z]{1,2}\s?\d{6}\s?\(\s?[0-9A]\s?\)', re.I), hkid_valid,
     "香港身份证号（mod-11 校验）"),
    ("CARD",      re.compile(r'\b(?:\d[ -]?){13,19}\b'), luhn_valid,
     "支付卡号（Luhn 校验）"),
    ("BANK_ACCT", re.compile(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3,9}\b'), hk_bank_acct_valid,
     "香港银行账号（清算行代码校验）"),
    # 护照号无校验算法，若不锚定上下文会吞掉交易参考号（TR20260412）与 ISIN（HK0000xxxx）
    ("PASSPORT",  re.compile(r'(?:护照|passport)\s*(?:号码?|no\.?|number)?\s*[:：]?\s*'
                             r'([A-Z]{1,2}\d{7,8})\b', re.I), None,
     "护照号（需上下文锚定）"),
    # 边界守卫 (?<![-\w]) / (?![-\w])：避免匹配到 INV-2026-2644 这类编号的内部片段
    ("PHONE_HK",  re.compile(r'(?:\+?852[-\s]?)?(?<![-\w])[2-9]\d{3}[-\s]?\d{4}(?![-\w])'), None,
     "香港电话号码"),
    ("EMAIL",     re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b'), None,
     "电子邮箱"),
    ("SWIFT",     re.compile(r'\b[A-Z]{4}HK(?:HH|H1|[A-Z0-9]{2})(?:[A-Z0-9]{3})?\b'), None,
     "SWIFT/BIC 代码"),
    # 带上下文锚点的中文姓名：仅在明确的字段标签后才识别，避免泛化误伤
    # 字段标签后【必须】有分隔符（冒号或空白），否则「账户持有人：X」会先匹配到
    # 「账户」，再把「持有人」误捕为人名。配合停用词表双重保险。
    ("NAME_CN",   re.compile(r'(?:账户持有人|客户姓名|投资者姓名|受益人姓名|申请人姓名|'
                             r'客户|账户|持有人|投资者|受益人|申请人|认购人|赎回人)'
                             r'(?:姓名|名称)?(?:[:：]\s*|\s+)([\u4e00-\u9fa5]{2,4})'), None,
     "客户姓名（标签+分隔符锚定，停用词过滤）"),
]

# 中文姓名位停用词：出现在字段标签后但并非人名的常见搭配
NAME_STOPWORDS = {
    "资料","名单","账户","信息","数据","明细","编号","地址","姓名","名称","记录","档案",
    "号码","账号","类型","状态","备注","余额","持仓","份额","认购","赎回","申请","查询",
    "列表","清单","报表","结构","风险","评级","电话","邮箱","证件","身份","护照","银行",
    "持有人","投资者","受益人","申请人","认购人","赎回人","客户","账户","姓名",
}

# 实体优先级：重叠时长实体与高置信实体优先
PRIORITY = {"HKID": 0, "CARD": 1, "BANK_ACCT": 2, "SWIFT": 3,
            "PASSPORT": 4, "EMAIL": 5, "PHONE_HK": 6, "NAME_CN": 7}


# ─────────────────────────── 密钥装载 ───────────────────────────

_SECRET_ENV = "GUARDRAIL_VAULT_SECRET"
_FALLBACK_SECRET = None

def load_secret() -> bytes:
    """
    Vault 的 HMAC 索引密钥。优先读环境变量；未配置时生成【进程级随机密钥】。
    绝不使用硬编码常量——占位符索引只需在单进程内自洽，随机密钥不影响功能，
    却避免了把可预测密钥写进交付物。
    """
    env = os.environ.get(_SECRET_ENV)
    if env:
        return env.encode() if isinstance(env, str) else env
    global _FALLBACK_SECRET
    if _FALLBACK_SECRET is None:
        _FALLBACK_SECRET = secrets.token_bytes(32)
        _LOG.warning("%s 未配置，已生成进程级随机密钥（重启后失效，不可跨进程还原）", _SECRET_ENV)
    return _FALLBACK_SECRET


class Vault:
    """
    占位符 ↔ 原值双向映射。键为 HMAC，占位符本身不含原值信息。

    生产级约束：
      · 线程安全    —— 所有写入在 threading.Lock 下完成。计数器自增是读-改-写
                       三步操作，无锁时存在占位符碰撞风险，一旦命中会让两个不同
                       客户的身份证还原为同一人，属数据完整性事故。
      · TTL         —— 每个条目带到期时间，默认 300 秒；读写时惰性回收过期条目。
      · 容量上限    —— 超过 max_entries 时按插入顺序淘汰最旧条目（LRU 近似），
                       防止长驻进程内存线性增长。
      · 显式销毁    —— purge() 清空映射；支持 with 语句，出站还原后即时销毁。
      · 密钥        —— 由环境变量注入，无硬编码。
    """

    DEFAULT_TTL = 300          # 秒；单次会话生命周期的保守上界
    DEFAULT_MAX = 10_000       # 条；单会话正常用量远低于此

    def __init__(self, secret: bytes = None, ttl_seconds: int = None,
                 max_entries: int = None):
        self.secret = secret if secret is not None else load_secret()
        self.ttl = self.DEFAULT_TTL if ttl_seconds is None else ttl_seconds
        self.max_entries = self.DEFAULT_MAX if max_entries is None else max_entries
        self._lock = threading.Lock()
        self.fwd = OrderedDict()      # token -> original
        self.by_hash = {}             # hmac  -> token
        self.counter = {}             # etype -> 序号
        self._expiry = {}             # token -> 到期单调时钟
        self._closed = False

    # ── 内部 ──
    def _h(self, val: str) -> str:
        return hmac.new(self.secret, val.encode(), hashlib.sha256).hexdigest()

    def _evict_locked(self):
        """须在持锁状态下调用：回收过期条目，并在超限时淘汰最旧条目。"""
        now = time.monotonic()
        for tok in [t for t, dl in self._expiry.items() if dl <= now]:
            self._drop_locked(tok)
        while len(self.fwd) > self.max_entries:
            self._drop_locked(next(iter(self.fwd)))

    def _drop_locked(self, tok: str):
        val = self.fwd.pop(tok, None)
        self._expiry.pop(tok, None)
        if val is not None:
            self.by_hash.pop(self._h(val), None)

    # ── 对外 ──
    def token_for(self, etype: str, val: str) -> str:
        if self._closed:
            raise RuntimeError("Vault 已销毁，不能继续写入")
        with self._lock:
            self._evict_locked()
            h = self._h(val)
            tok = self.by_hash.get(h)
            if tok is not None:                      # 同一原值复用同一占位符
                self._expiry[tok] = time.monotonic() + self.ttl
                return tok
            self.counter[etype] = self.counter.get(etype, 0) + 1
            tok = f"[{etype}_{self.counter[etype]}]"
            self.by_hash[h] = tok
            self.fwd[tok] = val
            self._expiry[tok] = time.monotonic() + self.ttl
            while len(self.fwd) > self.max_entries:      # 插入后修剪
                self._drop_locked(next(iter(self.fwd)))
            return tok

    def restore(self, text: str) -> str:
        """按权限回填原值。已过期或已销毁的条目不再还原，占位符原样保留。"""
        with self._lock:
            self._evict_locked()
            items = list(self.fwd.items())
        for tok, val in items:
            text = text.replace(tok, val)
        return text

    def purge(self):
        """显式销毁映射。出站还原完成后应立即调用。"""
        with self._lock:
            self.fwd.clear(); self.by_hash.clear()
            self._expiry.clear(); self.counter.clear()
            self._closed = True

    def __len__(self):
        return len(self.fwd)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.purge()
        return False

    def __del__(self):
        try: self.purge()
        except Exception: pass


def find_entities(text: str):
    """返回 [(start, end, etype, value)]，已做重叠消解"""
    hits = []
    for etype, rx, validator, _ in RULES:
        for m in rx.finditer(text):
            raw = m.group(1) if (etype == "NAME_CN" and m.groups()) else m.group(0)
            span = m.span(1) if (etype == "NAME_CN" and m.groups()) else m.span(0)
            if validator and not validator(raw):
                continue
            if etype == "NAME_CN" and raw.strip() in NAME_STOPWORDS:
                continue
            # 跨度收缩到 strip 后的实体本身，避免把首尾空白卷入占位符。
            # （卡号正则 \b(?:\d[ -]?){13,19}\b 会吞掉尾部空格，
            #   不收缩会导致脱敏还原后缺失该空格，破坏可逆性。）
            lead  = len(raw) - len(raw.lstrip())
            trail = len(raw) - len(raw.rstrip())
            hits.append((span[0] + lead, span[1] - trail, etype, raw.strip()))
    # 重叠消解：先按起点，再按「跨度长 / 优先级高」
    hits.sort(key=lambda h: (h[0], -(h[1] - h[0]), PRIORITY.get(h[2], 99)))
    kept, last_end = [], -1
    for h in hits:
        if h[0] >= last_end:
            kept.append(h); last_end = h[1]
    return kept


def mask(text: str, vault: Vault = None):
    """返回 (脱敏文本, vault, 命中实体列表)"""
    vault = Vault() if vault is None else vault   # 不可用 `or`：__len__ 为 0 时空 Vault 判假
    ents = find_entities(text)
    out, prev = [], 0
    for s, e, etype, val in ents:
        out.append(text[prev:s])
        out.append(vault.token_for(etype, val))
        prev = e
    out.append(text[prev:])
    return "".join(out), vault, ents

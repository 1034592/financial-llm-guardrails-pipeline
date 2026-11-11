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
import re, hmac, hashlib, unicodedata
from collections import OrderedDict

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


class Vault:
    """占位符 ↔ 原值双向映射。键为 HMAC，占位符本身不含原值信息。"""
    def __init__(self, secret: bytes = b"asset-b-demo-key"):
        self.secret = secret
        self.fwd = OrderedDict()   # token -> original
        self.by_hash = {}          # hmac -> token
        self.counter = {}

    def _h(self, val: str) -> str:
        return hmac.new(self.secret, val.encode(), hashlib.sha256).hexdigest()

    def token_for(self, etype: str, val: str) -> str:
        h = self._h(val)
        if h in self.by_hash:
            return self.by_hash[h]              # 同一原值复用同一占位符
        self.counter[etype] = self.counter.get(etype, 0) + 1
        tok = f"[{etype}_{self.counter[etype]}]"
        self.by_hash[h] = tok
        self.fwd[tok] = val
        return tok

    def restore(self, text: str) -> str:
        for tok, val in self.fwd.items():
            text = text.replace(tok, val)
        return text


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
    vault = vault or Vault()
    ents = find_entities(text)
    out, prev = [], 0
    for s, e, etype, val in ents:
        out.append(text[prev:s])
        out.append(vault.token_for(etype, val))
        prev = e
    out.append(text[prev:])
    return "".join(out), vault, ents

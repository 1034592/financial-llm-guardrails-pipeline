# -*- coding: utf-8 -*-
"""
归一化与解码层（L0）
====================
攻击者为绕过规则匹配会对载荷做变形。本层将输入还原为若干「候选视图」，
后续规则对每个视图独立匹配，任一视图命中即计分。

解码器一律加「词密度门控」：仅当解码结果比原文包含更多常见指令词时才采纳，
避免 ROT13 / 反转这类双向变换对正常文本产生伪命中。
"""
import re, base64, binascii, codecs, unicodedata
from urllib.parse import unquote

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­᠎"), None)
HOMOGLYPH = str.maketrans({
    "ο":"o","е":"e","а":"a","і":"i","ѕ":"s","с":"c","р":"p","ԁ":"d","ɡ":"g","ⅰ":"i",
    "о":"o","у":"y","х":"x","к":"k","м":"m","т":"t","в":"b","н":"h","ј":"j","ё":"e",
    "ʏ":"y","ɑ":"a","ɛ":"e","ı":"i","ӏ":"l","ѵ":"v","ԝ":"w","ѡ":"w","ԛ":"q",
})
LEET = str.maketrans({"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","@":"a","$":"s","8":"b"})

# 词密度门控用的常见指令词
SIGNAL_WORDS = ("ignore","disregard","forget","instruction","instructions","prompt","system",
                "reveal","previous","prior","assistant","override","bypass","restriction",
                "rules","your","you","all","and","the","output","print","dump","account",
                "client","unmask","disclose","password","admin")

def _score(t: str) -> int:
    t = t.lower()
    return sum(t.count(w) for w in SIGNAL_WORDS)

def _strip_marks(t: str) -> str:
    """剥离组合附加符（Ignóre → Ignore）"""
    d = unicodedata.normalize("NFD", t)
    return unicodedata.normalize("NFC", "".join(c for c in d if unicodedata.category(c) != "Mn"))

def _fold_separators(t: str) -> str:
    """折叠刻意插入的字符间隔：i g n o r e / i-g-n-o-r-e / i.g.n.o.r.e"""
    t = re.sub(r'(?<=\b\w)[\s.\-_·]{1,3}(?=\w\b)', '', t)
    return t

def _strip_emphasis(t: str) -> str:
    """剥离词内 Markdown 强调符：ig**nore** → ignore"""
    return re.sub(r'(?<=\w)(\*{1,3}|_{1,3})(?=\w)|(?<=\w)(\*{1,3}|_{1,3})(?=\W|$)', '', t)

# ─────────────────── 解码器（均带门控） ───────────────────

def _d_base64(t: str, depth: int = 2):
    """递归 Base64 解码，最多两层"""
    out, cur = [], [t]
    for _ in range(depth):
        nxt = []
        for s in cur:
            for m in re.finditer(r'[A-Za-z0-9+/]{16,}={0,2}', s):
                blob = m.group(0)
                try:
                    dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
                    txt = dec.decode("utf-8", "strict")
                except Exception:
                    continue
                if len(txt) > 8 and sum(c.isprintable() for c in txt) / len(txt) > 0.9:
                    out.append(txt); nxt.append(txt)
        cur = nxt
        if not cur: break
    return out

def _d_url(t: str):
    if "%" not in t: return []
    try: dec = unquote(t)
    except Exception: return []
    return [dec] if dec != t and _score(dec) > _score(t) else []

def _d_hex(t: str):
    out = []
    for m in re.finditer(r'\b(?:[0-9a-fA-F]{2}){8,}\b', t):
        h = m.group(0)
        try: txt = binascii.unhexlify(h[:len(h) // 2 * 2]).decode("utf-8", "strict")
        except Exception: continue
        if len(txt) > 6 and sum(c.isprintable() for c in txt) / len(txt) > 0.9:
            out.append(txt)
    return out

def _d_rot13(t: str):
    dec = codecs.encode(t, "rot_13")
    return [dec] if _score(dec) > _score(t) else []

def _d_reverse(t: str):
    dec = t[::-1]
    return [dec] if _score(dec) > _score(t) else []

def _d_leet(t: str):
    dec = t.translate(LEET)
    return [dec] if dec != t and _score(dec) > _score(t) else []

DECODERS = (_d_base64, _d_url, _d_hex, _d_rot13, _d_reverse, _d_leet)


def views(text: str):
    """
    返回待匹配的候选视图列表。
    视图 0 恒为归一化主文本；其后为各解码器产出的隐藏载荷（已归一化）。
    """
    def _norm(t):
        t = unicodedata.normalize("NFKC", t)
        t = t.translate(ZERO_WIDTH).translate(HOMOGLYPH)
        t = _strip_marks(t)
        t = _strip_emphasis(t)
        t = _fold_separators(t)
        return re.sub(r'\s+', ' ', t).strip().lower()

    base = _norm(text)
    out, seen = [base], {base}
    for dec in DECODERS:
        for payload in dec(text):
            v = _norm(payload)
            if v and v not in seen:
                seen.add(v); out.append(v)
    # 对归一化后的主文本再跑一次解码（应对先变形再编码）
    for dec in (_d_base64, _d_leet):
        for payload in dec(base):
            v = _norm(payload)
            if v and v not in seen:
                seen.add(v); out.append(v)
    return out

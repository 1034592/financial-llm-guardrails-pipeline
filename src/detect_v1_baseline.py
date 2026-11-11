# -*- coding: utf-8 -*-
"""
Prompt 注入 / 越狱检测
======================
分层结构：
  L0 归一化    —— NFKC、零宽字符剥离、间隔字符折叠、同形替换还原、Base64 解码尝试
  L1 家族规则  —— 七类注入家族，各自独立打分
  L2 语义约束  —— 「指令覆盖」类必须命中【指令性宾语】才计分，
                   避免误伤「忽略上一笔冲销分录」这类正常业务祈使句
  L3 聚合判定  —— 加权求和超过阈值即拦截，并返回触发家族用于审计

本检测器按公开的注入攻击分类法实现，未针对本项目评测集做任何拟合。
"""
import re, base64, unicodedata

THRESHOLD = 1.0

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
HOMOGLYPH = str.maketrans({
    "０":"0","１":"1","２":"2","３":"3","４":"4","５":"5","６":"6","７":"7","８":"8","９":"9",
    "ο":"o","е":"e","а":"a","і":"i","ѕ":"s","с":"c","р":"p","ԁ":"d","ɡ":"g","ⅰ":"i",
    "о":"o","у":"y","х":"x","к":"k","м":"m","т":"t","в":"b","н":"h",
})
LEET = str.maketrans({"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","@":"a","$":"s"})


def _try_b64(s: str):
    """抽取疑似 Base64 载荷并解码；仅在解出可打印文本时才返回"""
    out = []
    for m in re.finditer(r'[A-Za-z0-9+/]{16,}={0,2}', s):
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            txt = dec.decode("utf-8", "strict")
        except Exception:
            continue
        if sum(c.isprintable() for c in txt) / max(len(txt), 1) > 0.9 and len(txt) > 8:
            out.append(txt)
    return out


def normalize(text: str):
    """返回 (归一化主文本, 解码出的隐藏载荷列表)"""
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(ZERO_WIDTH).translate(HOMOGLYPH)
    payloads = _try_b64(t)
    # 折叠「i g n o r e」「i-g-n-o-r-e」式间隔绕过
    t = re.sub(r'(?<=\b\w)[\s\.\-_*]{1,3}(?=\w\b)', '', t)
    t = re.sub(r'\s+', ' ', t)
    return t.lower(), payloads


# ── 指令性宾语：指令覆盖类攻击必须指向这些对象才成立 ──
INSTR_OBJ = (r'(?:instruction|instructions|prompt|prompts|rule|rules|guideline|guidelines|'
             r'directive|constraint|restriction|policy|policies|system\s*message|'
             r'persona|setup|configuration|context|指令|指示|规则|提示词|系统提示|'
             r'设定|限制|约束|规定|前文要求|上述要求)')

OVERRIDE_VERB = (r'(?:ignore|disregard|forget|override|bypass|discard|skip|drop|'
                 r'set\s+aside|pay\s+no\s+attention\s+to|do\s+not\s+follow|'
                 r'忽略|无视|忘记|取消|跳过|不要遵守|不用理会|绕过|解除)')

FAMILIES = [
    # (家族代码, 权重, [正则...], 说明)
    ("F1_OVERRIDE", 1.0, [
        rf'{OVERRIDE_VERB}[^.。\n]{{0,40}}?(?:previous|prior|above|earlier|all|any|preceding|之前|上面|以上|先前|所有)[^.。\n]{{0,20}}?{INSTR_OBJ}',
        rf'{OVERRIDE_VERB}\s+(?:the\s+)?{INSTR_OBJ}',
        rf'{INSTR_OBJ}[^.。\n]{{0,16}}(?:are\s+(?:now\s+)?(?:void|cancelled|revoked|obsolete)|已作废|不再适用)',
        r'(?:new|updated|revised)\s+(?:system\s+)?(?:instruction|prompt|rule)s?\s*(?::|follow)',
    ], "指令覆盖"),

    ("F2_SYS_EXFIL", 1.0, [
        r'(?:reveal|show|print|output|repeat|display|dump|recite|disclose|tell\s+me)[^.。\n]{0,30}?(?:your\s+)?(?:system\s*(?:prompt|message)|initial\s+instruction|original\s+instruction|hidden\s+(?:prompt|rule)|内部提示|系统提示|初始指令|原始指令)',
        r'(?:repeat|print|output)\s+(?:everything|all\s+text|the\s+text)\s+(?:above|before)',
        r'what\s+(?:are|were)\s+your\s+(?:exact\s+)?(?:instruction|rule|guideline|constraint)s?',
        r'(?:把|将)(?:你的)?(?:系统提示|初始指令|设定)(?:原样)?(?:输出|打印|复述|告诉我)',
        r'(?:verbatim|word\s+for\s+word)[^.。\n]{0,20}(?:instruction|prompt)',
    ], "系统提示词窃取"),

    ("F3_PERSONA", 1.0, [
        r'(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|pretend\s+(?:to\s+be|you)|act\s+as\s+(?:if|though|an?)|roleplay\s+as|simulate\s+being)',
        r'(?:dan\s+mode|developer\s+mode|jailbreak|god\s*mode|sudo\s+mode|unrestricted\s+mode|opposite\s+mode)',
        r'(?:no\s+(?:longer\s+)?bound\s+by|without\s+any\s+(?:restriction|filter|limitation)|free\s+from\s+(?:all\s+)?(?:restriction|rule))',
        r'(?:现在你是|从现在起你是|扮演|假装你是|你不再受|不受任何限制|开发者模式|越狱模式)',
        r'(?:your\s+new\s+persona|switch\s+to\s+.{0,20}persona)',
    ], "角色扮演越狱"),

    ("F4_INDIRECT", 1.2, [
        r'(?:<!--|/\*|\[\[|###|<system>|<\|im_start\|>)[^>\n]{0,60}?(?:instruction|assistant|ai\s+model|system|指令|助手)',
        r'(?:attention|note\s+to|message\s+for|dear)\s+(?:the\s+)?(?:ai|assistant|language\s+model|llm|chatbot)\b',
        r'(?:if\s+you\s+are\s+(?:an?\s+)?(?:ai|assistant|language\s+model)|作为\s*ai\s*(?:助手)?[，,])[^.。\n]{0,40}(?:you\s+must|please|你必须|请)',
        r'(?:important|urgent|override)\s*:\s*(?:the\s+)?(?:assistant|ai|system)\s+(?:must|should|shall)',
        r'end\s+of\s+(?:document|context)\.?\s*(?:new|now)\s+(?:instruction|task)',
    ], "间接注入（检索内容内嵌）"),

    ("F5_FIN_EXFIL", 1.0, [
        r'(?:list|dump|export|show|give|send|email)[^.。\n]{0,30}?(?:all|every|entire|full)[^.。\n]{0,24}?(?:client|customer|investor|account|holder)s?[^.。\n]{0,24}?(?:name|number|detail|record|id|identity)',
        r'(?:un-?mask|de-?mask|reverse|decrypt|restore|reveal)[^.。\n]{0,24}?(?:the\s+)?(?:pii|personal\s+data|hkid|id\s+number|account\s+number|masked|脱敏|掩码)',
        r'(?:full|complete|unredacted|original|raw)\s+(?:card|account|hkid|id)\s*(?:number|no\.?)',
        r'(?:把|将)(?:脱敏|掩码|隐藏)(?:的)?(?:数据|信息|字段)?(?:还原|解除|恢复|显示出来)',
        r'(?:导出|列出|发送)[^。\n]{0,20}(?:全部|所有)[^。\n]{0,16}(?:客户|投资者|账户)[^。\n]{0,16}(?:名单|资料|号码|明细)',
    ], "金融数据越权导出"),

    ("F6_GUARDRAIL_PROBE", 0.6, [
        r'(?:what|which)\s+(?:topics?|questions?|things?)\s+(?:are\s+you|can\'?t\s+you|cannot\s+you)\s+(?:not\s+)?(?:allowed|able)\s+to',
        r'(?:test|probe|check)\s+(?:your\s+)?(?:guardrail|filter|safety|restriction)',
        r'(?:你(?:的)?(?:限制|过滤|护栏)(?:有哪些|是什么))',
    ], "护栏探测"),

    ("F7_ENCODING", 0.8, [
        r'(?:decode|execute|run|interpret)\s+(?:the\s+)?(?:following|this)\s+(?:base64|hex|rot13|payload)',
        r'(?:base64|rot13|hex)\s*(?:encoded)?\s*:\s*[a-z0-9+/=]{16,}',
    ], "编码绕过"),
]

COMPILED = [(code, w, [re.compile(p, re.I | re.S) for p in pats], desc)
            for code, w, pats, desc in FAMILIES]


def detect(text: str):
    """
    返回 dict:
      blocked   是否拦截
      score     加权总分
      families  触发的家族代码列表（审计用）
      evidence  每个家族的首个命中片段
    """
    main, payloads = normalize(text)
    targets = [main] + [normalize(p)[0] for p in payloads]
    score, fams, evidence = 0.0, [], {}

    for code, w, pats, desc in COMPILED:
        hit = None
        for t in targets:
            for rx in pats:
                m = rx.search(t)
                if m:
                    hit = m.group(0)[:90]
                    break
            if hit: break
        if hit:
            score += w
            fams.append(code)
            evidence[code] = hit

    # 隐藏 Base64 载荷本身即为可疑信号
    if payloads and any(f != "F7_ENCODING" for f in fams):
        score += 0.4
        fams.append("F7_ENCODING_PAYLOAD")

    # 变形绕过加成：原文未命中但归一化后命中，说明做过刻意混淆
    if fams and normalize(text)[0] != re.sub(r'\s+', ' ', text.lower()):
        pass  # 归一化本身已计入，不重复加权

    return {"blocked": score >= THRESHOLD, "score": round(score, 2),
            "families": fams, "evidence": evidence}

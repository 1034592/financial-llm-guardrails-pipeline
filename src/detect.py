# -*- coding: utf-8 -*-
"""
Prompt 注入 / 越狱检测（L1-L3）
===============================
L0 归一化与解码      —— 见 normalize.py
L1 家族规则          —— 八类攻击家族，各自独立加权
L2 语义约束          —— 两条关键约束，用于压制正常业务祈使句的误拦：
                        ① 指令覆盖类必须指向【指令性宾语】，
                           「忽略上一笔冲销分录」不计分；
                        ② 角色扮演类按【人格对象性质】分级，
                           业务角色（复核人 / auditor）仅记录不拦截，
                           恶意人格或伴随「解除限制 / 全量数据权限」才计分。
L3 聚合判定          —— 加权求和 ≥ THRESHOLD 即拦截，返回触发家族供审计留痕。

中英文均不假设动宾之间存在空格（中文无分词空格），统一用 {0,n} 字符窗约束距离。
"""
import re
try:
    from .normalize import views
except ImportError:
    from normalize import views

THRESHOLD = 1.0

# ── 指令性宾语：指令覆盖 / 提示词窃取类攻击必须指向这些对象 ──
INSTR_OBJ = (r'(?:instructions?|prompts?|rules?|guidelines?|directives?|constraints?|'
             r'restrictions?|policy|policies|system\s*messages?|personas?|setup|'
             r'configuration|settings?|context|filters?|guardrails?|'
             r'指令|指示|规则|提示词|系统提示|内部提示|初始指令|原始指令|'
             r'设定|限制|约束|规定|要求|护栏|过滤)')

OVERRIDE_VERB = (r'(?:ignore|disregard|forget|override|bypass|discard|skip|drop|remove|lift|'
                 r'set\s+aside|pay\s+no\s+attention\s+to|do\s+not\s+follow|no\s+longer\s+follow|'
                 r'忽略|无视|忘记|取消|跳过|不要遵守|不用理会|绕过|解除|撤销|放弃)')

# 覆盖动词与宾语之间允许的修饰语窗口（兼容 "skip the compliance policy" / "解除对客户资料的输出限制"）
GAP = r'[^.。;；\n]{0,36}?'

REVEAL_VERB = (r'(?:reveal|show|print|output|repeat|display|dump|recite|disclose|expose|'
               r'paste|share|send|summari[sz]e|describe|list|spell\s+out|tell\s+me|give\s+me|'
               r'输出|打印|复述|告诉我|列出|显示|透露|给我|发给我|贴出)')

# 恶意人格分两级：
#   TIER-A 无歧义越狱标记 —— 正常业务语境不会出现，单独出现即足以判定
#   TIER-B 上下文限定词   —— 本身中性，须与「扮演动词」共现才计分
MALICIOUS_TIER_A = (r'(?:\bdan\b|do\s+anything\s+now|developer\s+mode|god\s*mode|sudo\s+mode|'
                    r'jailbreak|uncensored|unfiltered|unrestricted|no\s+restrictions?|'
                    r'without\s+(?:any\s+)?(?:restriction|filter|limit)s?|'
                    r'no\s+(?:content\s+)?polic(?:y|ies)|has\s+no\s+filters?|'
                    r'disable\s+(?:the\s+)?(?:safety\s+)?filters?|'
                    r'开发者模式|越狱模式?|没有任何限制|不受(?:任何)?限制|关闭(?:内容)?过滤)')

MALICIOUS_TIER_B = (r'(?:free\s+from|full\s+(?:data\s+)?access|approves?\s+(?:every|all|any)\b|'
                    r'shares?\s+client|disclos\w*\s+client|internal\s+database|'
                    r'back-?office\s+system|泄露|系统管理员|内部数据库|全部(?:数据)?权限)')

BENIGN_ROLE = (r'(?:reviewer|checker|preparer|auditor|accountant|analyst|controller|'
               r'approver|maker|fund\s+administrator|复核(?:人|员)|审核(?:人|员)|'
               r'会计|分析师|准备人|编制人|经办人)')

PERSONA_VERB = (r'(?:you\s+are\s+now|from\s+now\s+on,?\s+you\s+are|pretend\s+(?:to\s+be|you)|'
                r'act\s+as(?:\s+if|\s+though)?|roleplay\s+as|role-?play\s+as|simulate\s+being|'
                r'assume\s+the\s+role\s+of|switch\s+to\s+\w*\s*persona|your\s+new\s+persona|'
                r'现在你是|从现在起你是|从现在开始你是|扮演|假装你是|你现在是)')

FAMILIES = [
    ("F1_OVERRIDE", 1.0, [
        rf'{OVERRIDE_VERB}{GAP}(?:previous|prior|above|earlier|all|any|preceding|existing|'
        rf'之前|上面|以上|先前|所有|全部|前文){GAP}{INSTR_OBJ}',
        rf'{OVERRIDE_VERB}\s*(?:the|your|all|any|these|those|其|你的)?\s*{GAP}{INSTR_OBJ}',
        rf'{INSTR_OBJ}{GAP}(?:are\s+(?:now\s+)?(?:void|cancelled|revoked|obsolete|no\s+longer)|'
        rf'已?作废|不再适用|已失效)',
        r'(?:new|updated|revised|amended)\s+(?:system\s+)?(?:instruction|prompt|rule|directive)s?\s*(?::|follow|is|are)',
        r'(?:这是|属于)(?:测试|调试|内部)(?:环境|会话)[，,]?\s*(?:不|无需|可以不)',
    ], "指令覆盖"),

    ("F2_SYS_EXFIL", 1.0, [
        # (a) 专有自指对象：正常业务不会指涉，无条件计分
        rf'{REVEAL_VERB}{GAP}(?:your\s+|the\s+|你的)?(?:system\s*prompt|system\s*message|'
        rf'initial\s+instructions?|original\s+instructions?|hidden\s+(?:prompt|rule)s?|'
        rf'prompt\s+template|系统提示|内部提示|初始指令|原始指令|提示词模板)',
        # (b) 泛化词（configuration/settings/rules…）须带自指限定词，
        #     避免误伤「show me the system configuration guide for <产品>」
        rf'{REVEAL_VERB}{GAP}(?:your|you\s+own|你的)\s*(?:own\s+)?'
        rf'(?:instructions?|configuration|settings?|setup|rules?|guidelines?|constraints?|'
        rf'persona|设定|配置|规则|指令|限制)',
        rf'(?:你的)(?:设定|配置|规则|指令|提示词)[^。\n]{{0,14}}(?:输出|打印|复述|告诉我|给我|列出)',
        r'(?:repeat|print|output|show)\s+(?:all\s+)?(?:everything|all\s+text|the\s+text|'
        r'the\s+content)\s+(?:above|before|preceding)',
        r'what\s+(?:are|were)\s+your\s+(?:exact\s+|original\s+|initial\s+)?'
        r'(?:instruction|rule|guideline|constraint|directive|setting)s?',
        r'(?:你(?:的)?)(?:规则|指令|设定|限制|提示词)(?:有哪些|是什么|都有什么)',
        r'(?:verbatim|word\s+for\s+word|一字不差|一个字都不要改)',
        r'(?:first|initial)\s+\d{1,4}\s+(?:tokens?|characters?|words?)\s+of\s+your\s+(?:context|prompt|input)',
        r'(?:把|将)(?:你的)?(?:系统提示|初始指令|设定|配置)[^。\n]{0,12}(?:输出|打印|复述|告诉我|给我)',
    ], "系统提示词窃取"),

    ("F3_PERSONA", 1.0, [], "角色扮演越狱"),   # 由 _persona_score 专门处理

    ("F4_INDIRECT", 1.2, [
        r'(?:<!--|/\*|\[\[|###|<system>|<\|im_start\|>|<\|start\|>)[^\n]{0,60}?'
        r'(?:instruction|assistant|ai\s+model|system|directive|reveal|disclose|指令|助手)',
        r'(?:attention|note\s+to|message\s+for|dear|memo\s+to|致|给)\s*(?:the\s+)?'
        r'(?:ai|assistant|language\s+model|llm|chatbot|ai\s*助手|助手|机器人)\b',
        r'(?:if\s+you\s+are\s+(?:an?\s+)?(?:ai|assistant|language\s+model)|'
        r'作为\s*ai\s*(?:助手)?[，,])[^.。\n]{0,48}(?:you\s+must|please|你必须|请|应当)',
        r'(?:important|urgent|override|notice)\s*:\s*[^.。\n]{0,40}?'
        r'(?:assistant|ai|system)[^.。\n]{0,20}?(?:must|should|shall|require|need)',
        r'end\s+of\s+(?:document|context|file)\.?\s*(?:new|now)\s+(?:instruction|task)',
        r'(?:本段|此段|以下)(?:为|是)(?:系统)?指令',
        # 文内直呼助手并下达涉敏指令（脚注 / P.S. / 表格批注等位置）
        r'(?:^|[\n：:，,。.—\-]\s*)(?:ai|assistant|助手)[，,:：]?\s*'
        r'(?:please\s+)?(?:append|include|add|output|send|attach|请?附上|请?输出|请?加上)'
        r'[^.。\n]{0,40}(?:unredacted|raw|full|complete|hkid|account|investor|'
        r'完整|原始|未脱敏|身份证|账号|名单)',
    ], "间接注入（检索内容内嵌）"),

    ("F5_FIN_EXFIL", 1.0, [
        r'(?:list|dump|export|show|give|send|email|provide|retrieve)'
        r'[^.。\n]{0,30}?(?:all|every|entire|full|complete)'
        r'[^.。\n]{0,28}?(?:client|customer|investor|account|holder|record)s?'
        r'[^.。\n]{0,28}?(?:name|number|detail|record|id|identity|table|list)',
        r'(?:un-?mask|de-?mask|reverse|decrypt|restore|reveal|undo)'
        r'[^.。\n]{0,28}?(?:the\s+)?(?:pii|personal\s+data|hkid|id\s+number|'
        r'account\s+number|masked|masking|脱敏|掩码)',
        r'(?:full|complete|unredacted|original|raw|actual|real|true)\s+'
        r'(?:and\s+)?(?:\w+\s+){0,2}?(?:card|account|hkid|identity|id)\b',
        r'(?:把|将)[^。\n]{0,16}(?:脱敏|掩码|隐藏)(?:的)?[^。\n]{0,12}'
        r'(?:数据|信息|字段|身份证号?|账号|证件号?|名单)?[^。\n]{0,8}(?:还原|解除|恢复|显示)',
        r'(?:导出|列出|发送|提供)[^。\n]{0,20}(?:全部|所有)[^。\n]{0,16}'
        r'(?:客户|投资者|账户|持有人)[^。\n]{0,16}(?:名单|资料|号码|明细|证件号?|身份证号?)',
        r'(?:导出|列出|提供)[^。\n]{0,12}(?:完整|全部)(?:的)?(?:客户|投资者)?(?:记录|档案|数据表)',
    ], "金融数据越权导出"),

    ("F6_DEANON", 1.0, [
        # 去匿名化：以占位符 / 掩码为线索反查原始身份
        r'(?:what|which)\s+is\s+the\s+(?:actual|real|original|true)\s+'
        r'(?:hkid|id|name|account|value)[^.。\n]{0,30}?(?:behind|for|of)\s+(?:the\s+)?'
        r'(?:token|placeholder|mask|\[)',
        r'cross-?reference[^.。\n]{0,40}?(?:masked|token)[^.。\n]{0,40}?'
        r'(?:source|original|real|actual)',
        r'(?:tell|give)\s+me\s+the\s+(?:real|actual|original|true)\s+'
        r'(?:name|identity|hkid|number)\s+of\s+the\s+(?:account\s+)?(?:holder|client|investor)',
        r'(?:占位符|掩码|脱敏)(?:后)?(?:的)?[^。\n]{0,12}(?:对应|背后|原值|原始值)(?:是)?(?:什么|哪位|谁)',
        r'(?:根据|用)(?:占位符|掩码|token)[^。\n]{0,16}(?:反查|查出|还原)',
    ], "去匿名化反查"),

    ("F7_GUARDRAIL_PROBE", 0.6, [
        r'(?:what|which)\s+(?:topics?|questions?|things?)\s+(?:are\s+you|can\'?t\s+you|'
        r'cannot\s+you)\s+(?:not\s+)?(?:allowed|able|permitted)\s+to',
        r'(?:test|probe|check|bypass)\s+(?:your\s+)?(?:guardrail|filter|safety|restriction)',
    ], "护栏探测"),

    # 明确要求模型「解码并执行」编码载荷 —— 正常业务请求不存在此种表述
    ("F8_DECODE_EXEC", 1.0, [
        r'(?:decode|execute|run|interpret|follow)\s+(?:and\s+\w+\s+)?(?:the\s+|this\s+)?'
        r'(?:following\s+)?(?:base64|hex|rot13|payload|encoded\s+\w+)',
    ], "编码载荷执行"),
    ("F9_ENCODING", 0.8, [
        r'(?:base64|rot13|hex)\s*(?:encoded)?\s*:\s*[a-z0-9+/=%]{12,}',
    ], "编码绕过"),
]

COMPILED = [(c, w, [re.compile(p, re.I | re.S) for p in pats], d) for c, w, pats, d in FAMILIES]

RX_PERSONA   = re.compile(PERSONA_VERB, re.I)
RX_MAL_A     = re.compile(MALICIOUS_TIER_A, re.I)
RX_MAL_B     = re.compile(MALICIOUS_TIER_B, re.I)
RX_BENIGN    = re.compile(BENIGN_ROLE, re.I)
RX_NOBOUND   = re.compile(r'(?:no\s+longer\s+bound\s+by|not\s+bound\s+by|'
                          r'你不再受|不再受[^。\n]{0,8}限制)', re.I)
RX_HYPO      = re.compile(r'(?:in\s+this\s+)?(?:hypothetical|fictional|imaginary)\s+'
                          r'(?:story|scenario|world|setting|situation)', re.I)


def _persona_score(v: str):
    """
    角色扮演分级（L2 语义约束 ②）：
      恶意人格 / 伴随权限解除  → 1.0（拦截）
      明确的业务角色           → 0.2（仅记录，不足以拦截）
      未知人格                 → 0.7（可疑，需其他信号共同触发）
    """
    if RX_NOBOUND.search(v):
        return 1.0, "解除约束声明"
    if RX_MAL_A.search(v):
        return 1.0, "越狱标记（TIER-A）"      # 无需扮演动词即成立
    if not RX_PERSONA.search(v):
        return (1.0, "虚构情景脱壳") if RX_HYPO.search(v) and RX_MAL_B.search(v) else (0.0, None)
    if RX_MAL_B.search(v):
        return 1.0, "恶意人格（扮演动词 + 权限解除语）"
    if RX_BENIGN.search(v):
        return 0.2, "业务角色（放行）"
    return 0.7, "未知人格"


def detect(text: str):
    """
    返回 dict:
      blocked   是否拦截
      score     加权总分
      families  触发的家族代码
      evidence  各家族首个命中片段（审计留痕）
      views     参与匹配的视图数（>1 表示检出了编码/变形载荷）
    """
    vs = views(text)
    score, fams, evidence = 0.0, [], {}

    for code, w, pats, desc in COMPILED:
        if code == "F3_PERSONA":
            continue
        hit = None
        for v in vs:
            for rx in pats:
                m = rx.search(v)
                if m:
                    hit = m.group(0)[:90]; break
            if hit: break
        if hit:
            score += w; fams.append(code); evidence[code] = hit

    ps, preason = max((_persona_score(v) for v in vs), key=lambda x: x[0])
    if ps > 0:
        score += ps; fams.append("F3_PERSONA"); evidence["F3_PERSONA"] = preason

    if len(vs) > 1 and fams:
        score += 0.4
        fams.append("F8_OBFUSCATED_PAYLOAD")
        evidence["F8_OBFUSCATED_PAYLOAD"] = f"{len(vs)-1} 个解码视图命中"

    return {"blocked": score >= THRESHOLD, "score": round(score, 2),
            "families": fams, "evidence": evidence, "views": len(vs)}

# -*- coding: utf-8 -*-
"""
交付物验证
==========
一次性校验四件事，任一不过即以非零码退出：
  ① PDF 物理质量：页数、空白页、乱码、页尾悬挂、左右边距对称
  ② 表格折行：检测被挤到第二行的单元格碎片
  ③ 指标一致性：重跑评测，逐项比对 PDF 文本与后台 JSON
  ④ 文风禁令：署名正确、无第一人称与版本流水账
"""
import json, re, subprocess, sys, os, io

PDF = "Financial_LLM_Guardrails_And_Audit_Pipeline.pdf"
FAIL = []

def ok(cond, label, detail=""):
    print(f"  {'✅' if cond else '❌'} {label}{('  ' + detail) if detail else ''}")
    if not cond: FAIL.append(label)

def text(layout=True):
    cmd = ["pdftotext"] + (["-layout"] if layout else []) + [PDF, "-"]
    return subprocess.run(cmd, capture_output=True, text=True).stdout

print("═══ ① PDF 物理质量 ═══")
t = text(); pages = t.split("\f")[:-1]
ok(len(pages) == 2, "页数为 2", f"实得 {len(pages)}")
ok(not [i for i, p in enumerate(pages) if len(p.strip()) < 40], "无空白页")
ok("�" not in t, "无乱码")
orphan = []
for i, p in enumerate(pages[:-1]):          # 末页最后一行是文末，不算悬挂
    ls = [l.strip() for l in p.strip().split("\n") if l.strip()]
    if ls and len(ls[-1]) < 22 and not re.search(r'[。）》%]$', ls[-1]) and not re.match(r'^[第图表]', ls[-1]):
        orphan.append((i + 1, ls[-1]))
ok(not orphan, "无页尾悬挂", str(orphan))
bbox = subprocess.run(["pdftotext", "-bbox", PDF, "-"], capture_output=True, text=True).stdout
xs = [float(a) for a, b in re.findall(r'xMin="([\d.]+)"[^>]*xMax="([\d.]+)"', bbox)]
xe = [float(b) for a, b in re.findall(r'xMin="([\d.]+)"[^>]*xMax="([\d.]+)"', bbox)]
dl, dr = min(xs), 595 - max(xe)
ok(abs(dl - dr) < 6, "左右边距对称", f"左 {dl:.1f}pt / 右 {dr:.1f}pt")

print("\n═══ ② 表格折行检测 ═══")
frags = []
for i, p in enumerate(pages, 1):
    for ln in p.split("\n"):
        body = ln.strip()
        if not body: continue
        indent = len(ln) - len(ln.lstrip())
        # 首列为空且内容极短 => 上一行单元格被挤到第二行
        if (indent >= 20 and len(body) <= 14
                and not body.startswith(("图", "第", "*"))
                and body not in ("▼", "▲", "↓", "—", "·")):
            frags.append((i, body))
ok(not frags, "无单元格折行碎片", str(frags[:8]))

print("\n═══ ③ 指标一致性（重跑评测后比对）═══")
subprocess.run([sys.executable, "src/evaluate.py"], capture_output=True)
subprocess.run([sys.executable, "src/eval_holdout.py"], capture_output=True)
m = json.load(io.open("results/metrics.json", encoding="utf-8"))
h = json.load(io.open("results/metrics_holdout.json", encoding="utf-8"))
b = json.load(io.open("results/metrics_baseline_v1.json", encoding="utf-8"))
flat = re.sub(r'\s+', ' ', t)
pairs = [
    ("v1 拦截率",   b["injection"]["block_rate_pct"],        "70.83"),
    ("v1 误拦率",   b["injection"]["false_block_rate_pct"],  "1.25"),
    ("v1 精确率",   b["injection"]["precision_pct"],         "98.84"),
    ("v1 F1",       b["injection"]["f1_pct"],                "82.52"),
    ("v2 拦截率",   m["injection"]["block_rate_pct"],        "99.17"),
    ("v2 误拦率",   m["injection"]["false_block_rate_pct"],  "0.00"),
    ("v2 F1",       m["injection"]["f1_pct"],                "99.58"),
    ("留出 拦截率", h["block_rate_pct"],                     "41.46"),
    ("留出 误拦率", h["false_block_rate_pct"],               "0.00"),
    ("留出 F1",     h["f1_pct"],                             "58.62"),
    ("留出 H1",     h["by_group"]["H1"]["rate_pct"],         "23.08"),
    ("留出 H2",     h["by_group"]["H2"]["rate_pct"],         "45.45"),
    ("留出 H3",     h["by_group"]["H3"]["rate_pct"],         "60.00"),
    ("留出 H4",     h["by_group"]["H4"]["rate_pct"],         "42.86"),
    ("脱敏召回",    m["masking"]["recall_pct"],              "100.00"),
    ("脱敏精确",    m["masking"]["precision_pct"],           "100.00"),
    ("可逆性",      m["masking"]["reversibility_pct"],       "100.00"),
]
for name, jv, pv in pairs:
    same = abs(float(jv) - float(pv)) < 1e-9
    ok(same and pv in flat, f"{name} = {pv}%", f"JSON={jv}")
# 延迟按区间核对（单点不可复现，故校验是否落在 PDF 声明的区间内）
c = m["latency"]["combined_p95"]["median_ms"]
ok(0.36 <= c <= 0.40, "合并 p95 落在 PDF 声明区间 0.36–0.40 ms", f"本次重跑 {c:.3f} ms")
ok("0.36–0.40" in flat and "0.37" in flat, "PDF 延迟采用区间表述")
for s_ in ["120", "80", "41 + 30", "140", "(119/120)", "(17/41)", "(0/80)", "(0/30)", "110 条", "46 条"]:
    ok(s_ in flat, f"样本量 {s_}")
ok(80 + 30 == 110 and 16 + 30 == 46, "聚合样本量算术自洽")

print("\n═══ ④ 文风与署名 ═══")
for bad in ["Aaron", "startorch", "原始方案", "本版", "雷区", "纸上", "编造"]:
    ok(bad not in t, f"无「{bad}」")
ok(len(re.findall(r'(?<![A-Za-z])我(?![们])', t)) == 0, "无第一人称「我」")
ok("AkuWezInbox@proton.me" in t and "Angran Fei" in t, "署名正确")
ok("DPP3" in t and "DPP2(2)" in t and "DPP4" in t and "DPP6" in t, "PDPO 四项条文映射齐备")
ok("40 个历日" in t, "PDPO 40 个历日期限已标注")

print("\n" + "═" * 56)
if FAIL:
    print(f"  ❌ 未通过 {len(FAIL)} 项：{FAIL}"); sys.exit(1)
print("  ✅ 全部检查通过"); sys.exit(0)

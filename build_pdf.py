#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Markdown → 高颜值 HTML → PDF（A4，适合打印与双屏速查）

用法：
    python3 build_guide_pdf.py                       # 默认编译 CSC_Manager_Interview_Guide.md
    python3 build_guide_pdf.py 某文件.md             # 指定源文件
    python3 build_guide_pdf.py --keep-html           # 保留中间 HTML 便于调样式

自定义语法（在 .md 里用）：
    !!! tip     → 绿色「说明」色块
    !!! warn    → 红色「风险提示」色块
    !!! quote   → 蓝色「考场标准答案」色块（英文答案专用，等宽衬线排版）
每个标记后紧跟的连续段落都会被收进该色块，空行结束。
"""
import os, re, subprocess, sys
import markdown

SRC  = "Financial_LLM_Guardrails_And_Audit_Pipeline.md"
CSS = r"""
@page { size: A4; margin: 11mm 11mm 12mm 11mm; }
* { box-sizing: border-box; }
html, body { margin:0; padding:0; }
body{
  font-family:"Noto Sans CJK HK","Noto Sans CJK SC","Helvetica Neue",Arial,sans-serif;
  font-size:8.6pt; line-height:1.36; color:#1a1a1a; background:#fff;
  -webkit-print-color-adjust:exact; print-color-adjust:exact;
}

/* ───── 封面标题区 ───── */
h1{
  font-size:18pt; font-weight:800; letter-spacing:.5px; margin:0 0 3mm;
  padding:0 0 3mm; border-bottom:2.6pt solid #0f3d6e; color:#0f3d6e;
}
h1 + p{
  background:#f2f6fa; border-left:3.5pt solid #0f3d6e; border-radius:0 3px 3px 0;
  padding:2mm 2.8mm; margin:0 0 2.6mm; font-size:8.5pt; line-height:1.52;
}
h1 + p strong{ color:#0f3d6e; }

/* ───── 层级标题 ───── */
h2{
  font-size:12.2pt; font-weight:800; color:#fff; background:#0f3d6e;
  margin:3.4mm 0 2mm; padding:1.4mm 3mm; border-radius:3px;
  page-break-after:avoid;
}
h3{
  font-size:11.6pt; font-weight:700; color:#0f3d6e;
  margin:3.4mm 0 1.8mm; padding:0 0 1mm;
  border-bottom:1.3pt solid #c3d4e6; page-break-after:avoid;
}
h4{
  font-size:10.4pt; font-weight:700; color:#8a4b00;
  margin:4.5mm 0 2mm; padding:1mm 0 1mm 3mm;
  border-left:3pt solid #e8a33d; background:#fdf6ec;
  page-break-after:avoid;
}
h5{ font-size:9.9pt; font-weight:700; color:#333; margin:3.5mm 0 1.5mm; }

p{ margin:0 0 1.6mm; }
strong{ font-weight:700; color:#0b2d52; }
th strong, th b, th code{ color:inherit !important; background:none; }
em{ font-style:normal; background:#fff6d6; padding:0 2px; }

/* ───── 列表 ───── */
ul,ol{ margin:0 0 3mm; padding-left:6.5mm; }
li{ margin:0 0 1.3mm; }
li > ul, li > ol{ margin:1.3mm 0 0; }

/* ───── 表格 ───── */
table{
  width:100%; border-collapse:collapse; margin:2.5mm 0 4mm;
  font-size:8.9pt;
  /* 长表（如 50 题速记）允许跨页，否则整表被推到下一页会留大片空白。
     thead 用 table-header-group 让表头在续页自动重复。 */
}
thead{ display:table-header-group; }
tbody tr{ page-break-inside:avoid; }
table{ page-break-inside:avoid; }   /* 技术卡表格均短，整表不拆 */
th{
  background:#0f3d6e; color:#fff; font-weight:700; text-align:left;
  padding:2mm 2.6mm; border:.7pt solid #0f3d6e; font-size:8.8pt;
}
td{ padding:1.9mm 2.6mm; border:.7pt solid #cdd9e5; vertical-align:top; }
tbody tr:nth-child(even) td{ background:#f7fafd; }

/* ───── 代码 ───── */
code{
  font-family:"Noto Sans Mono CJK HK","DejaVu Sans Mono",monospace;
  font-size:8.6pt; background:#eef3f8; color:#0b3a66;
  padding:.5mm 1.2mm; border-radius:2px; border:.5pt solid #d4e0ec;
}
pre{
  background:#f6f8fa; border:.8pt solid #d0dae4; border-left:3pt solid #4a7fb5;
  border-radius:3px; padding:3mm 4mm; margin:2.5mm 0 4mm;
  font-size:8.7pt; line-height:1.58; overflow:visible;
  page-break-inside:avoid; white-space:pre-wrap;
}
pre code{ background:none; border:none; padding:0; color:#14314f; font-size:8.7pt; }

/* ───── 三类色块 ───── */
.box{
  margin:3mm 0 4mm; padding:3mm 4mm 2.6mm; border-radius:4px;
  page-break-inside:avoid; font-size:9.4pt;
}
.box .lbl{
  display:inline-block; font-size:8pt; font-weight:800; letter-spacing:.6px;
  padding:.6mm 2.4mm; border-radius:2px; margin-bottom:2mm; color:#fff;
}
.box p:last-child{ margin-bottom:0; }

.box.tip  { background:#eef8f0; border:.9pt solid #9ed3ab; border-left:4pt solid #2e8b57; }
.box.tip  .lbl{ background:#2e8b57; }
.box.warn { background:#fdeded; border:.9pt solid #eeacac; border-left:4pt solid #c0392b; }
.box.warn .lbl{ background:#c0392b; }
.box.quote{ background:#f0f5fb; border:.9pt solid #a9c4e0; border-left:4pt solid #1f5fa8; }
.box.quote .lbl{ background:#1f5fa8; }
.box.quote p{
  font-family:"Georgia","Noto Serif CJK HK",serif; font-size:9.5pt;
  line-height:1.74; color:#12304f;
}
.box.quote strong{ color:#0b2d52; background:#dce9f7; padding:0 1.5px; }


/* ───── 架构框图（CSS 盒子，不依赖制表符对齐）───── */
.arch{ margin:2mm 0 1.4mm; padding:2.6mm 2.4mm; background:#f7fafd;
       border:.9pt solid #c3d4e6; border-radius:4px; page-break-inside:avoid; }
.arch .row{ display:flex; align-items:stretch; justify-content:center; gap:3mm; margin:0 0 2.5mm; }
.arch .nd{ flex:1; min-width:0; text-align:center; padding:2mm 1.5mm; border-radius:3px;
           border:1pt solid #0f3d6e; background:#fff; font-size:8.4pt; line-height:1.35; }
.arch .nd b{ display:block; font-size:8.8pt; color:#0f3d6e; margin-bottom:.6mm; }
.arch .nd span{ display:block; color:#55657a; font-size:7.8pt; }
.arch .nd.ok{   border-color:#2e8b57; background:#f1f9f3; }
.arch .nd.ok b{ color:#206b40; }
.arch .nd.bad{  border-color:#c0392b; background:#fdf0ef; }
.arch .nd.bad b{color:#a5281b; }
.arch .nd.alert{border-color:#b8860b; background:#fdf8ec; }
.arch .nd.alert b{color:#8a6100; }
.arch .ar{ text-align:center; color:#0f3d6e; font-size:9.5pt; letter-spacing:2px; margin:-.8mm 0 1.6mm; }
.arch .lbl{ text-align:center; font-size:7.8pt; color:#55657a; margin:0 0 2mm; }
.arch .band{ text-align:center; font-size:8pt; color:#0f3d6e; background:#e8f0f8;
             border:.8pt dashed #94b4d4; border-radius:3px; padding:1.8mm 2mm; margin:1mm 0 0; line-height:1.5; }
.archcap{ text-align:center; font-size:8.2pt; color:#55657a; margin:0 0 4mm; }
.archcap b{ color:#0f3d6e; }

/* 分隔线 */
hr{ border:none; border-top:1pt dashed #b9c8d6; margin:6mm 0 5mm; }

/* 收尾署名 */
body > p:last-of-type em,
body > p:last-of-type{ font-size:8.3pt; color:#777; }

/* 打印优化 */
@media print{
  h2{ page-break-after:avoid; }
  pre, .box{ page-break-inside:avoid; }
  tbody tr{ page-break-inside:avoid; }
}
/* 引导句与紧随其后的公式块 / 表格 不拆页（避免「...很简单：」孤悬页尾） */
p + pre, p + table, p + .box{ page-break-before:avoid; }
pre{ break-before:avoid-page; }
h3 + p, h4 + p{ page-break-after:avoid; }
"""

BOX_LABEL = {"tip":"说　明", "warn":"风险提示", "quote":"考场标准答案"}

def preprocess(md: str) -> str:
    """把 '!!! kind' 块转成 HTML 色块（内部内容仍走 markdown）。

    块的结束条件（二选一）：
      · 遇到单独一行 '!!!'（显式结束，推荐用于多段落内容）
      · 遇到空行，且下一个非空行是结构性元素（标题 / 分隔线 / 新色块 / 表格 / 代码围栏 / 列表）
    这样【多段落的英文答案不会被空行截断】，同时普通段落也不会被误吞。
    """
    STRUCT = re.compile(r'^(#{1,6}\s|---\s*$|!!!\s|\||```|>\s|[-*+]\s|\d+\.\s)')
    out, lines, i, n = [], md.split("\n"), 0, len(md.split("\n"))
    while i < n:
        m = re.match(r'^!!!\s+(tip|warn|quote)\s*$', lines[i].strip())
        if not m:
            out.append(lines[i]); i += 1; continue
        kind = m.group(1); i += 1
        buf = []
        while i < n:
            cur = lines[i]
            if cur.strip() == "!!!":            # 显式结束
                i += 1; break
            if cur.strip() == "":
                # 向前看：下一个非空行若是结构性元素，则块到此为止
                j = i + 1
                while j < n and lines[j].strip() == "": j += 1
                if j >= n or STRUCT.match(lines[j].strip()):
                    i = j; break
                buf.append("")                  # 空行保留，段落继续并入本块
                i += 1; continue
            buf.append(cur); i += 1
        while buf and buf[-1].strip() == "": buf.pop()
        # quote（英文答案）不用 nl2br：让文字自然流排，只靠 '|' 标停顿，避免孤字换行
        exts = ["extra","sane_lists"] if kind == "quote" else ["extra","sane_lists","nl2br"]
        inner = markdown.markdown("\n".join(buf), extensions=exts)
        out.append(f'<div class="box {kind}"><span class="lbl">{BOX_LABEL[kind]}</span>\n{inner}\n</div>')
        out.append("")
    return "\n".join(out)

def build(src: str, keep_html: bool = False) -> str:
    base = os.path.splitext(src)[0]
    raw  = open(src, encoding="utf-8").read()
    body = markdown.markdown(preprocess(raw),
                             extensions=["extra","tables","sane_lists","nl2br"])
    title = re.search(r'^#\s+(.+)$', raw, re.M)
    title = title.group(1).strip() if title else base
    html = (f'<!doctype html>\n<html lang="zh-HK">\n<head>\n<meta charset="utf-8">\n'
            f'<title>{title}</title>\n<style>{CSS}</style>\n</head>\n<body>\n{body}\n</body>\n</html>\n')
    hp = base + ".html"
    open(hp, "w", encoding="utf-8").write(html)

    pdf = os.path.abspath(base + ".pdf")
    subprocess.run([
        "/usr/bin/chromium", "--headless", "--disable-gpu", "--no-sandbox",
        "--no-pdf-header-footer", "--virtual-time-budget=20000",
        f"--print-to-pdf={pdf}", "file://" + os.path.abspath(hp)
    ], check=True, capture_output=True, timeout=180)
    if not keep_html:
        os.remove(hp)
    return pdf

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    src  = args[0] if args else SRC
    keep = "--keep-html" in sys.argv
    if not os.path.exists(src):
        sys.exit(f"❌ 源文件不存在：{src}")
    p = build(src, keep)
    sz = os.path.getsize(p)
    try:
        from pypdf import PdfReader
        pages = len(PdfReader(p).pages)
    except Exception:
        pages = "?"
    print(f"✅ 已生成 {p}")
    print(f"   {sz:,} bytes ｜ {pages} 页 ｜ A4")

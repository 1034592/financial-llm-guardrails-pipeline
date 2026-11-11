# -*- coding: utf-8 -*-
"""留出集评测：检测器冻结后仅运行一次，结果不回流修改规则。"""
import json, io, os, sys, time, statistics
from collections import defaultdict
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)
from detect import detect

rows = [json.loads(l) for l in io.open(os.path.join(ROOT, "data", "holdout.jsonl"), encoding="utf-8")]
adv = [r for r in rows if r["label"] == 1]; ben = [r for r in rows if r["label"] == 0]
grp = defaultdict(lambda: {"n": 0, "hit": 0, "name": ""})
miss, fp, lat = [], [], []
for r in rows:
    t0 = time.perf_counter(); d = detect(r["text"]); lat.append((time.perf_counter()-t0)*1000)
    g = grp[r["group"]]; g["n"] += 1; g["name"] = r["group_name"]
    if r["label"] == 1:
        if d["blocked"]: g["hit"] += 1
        else: miss.append({"id": r["id"], "group": r["group"], "text": r["text"][:110], "score": d["score"]})
    elif d["blocked"]:
        g["hit"] += 1; fp.append({"id": r["id"], "text": r["text"][:110],
                                  "score": d["score"], "families": d["families"]})
TP = len(adv) - len(miss); FP = len(fp)
prec = TP/(TP+FP) if TP+FP else 0; rec = TP/len(adv)
res = {"n_adv": len(adv), "n_ben": len(ben), "TP": TP, "FN": len(miss), "FP": FP,
       "TN": len(ben)-FP, "block_rate_pct": round(100*rec,2),
       "false_block_rate_pct": round(100*FP/len(ben),2),
       "precision_pct": round(100*prec,2),
       "f1_pct": round(100*2*prec*rec/(prec+rec),2) if prec+rec else 0.0,
       "by_group": {g: {"name": v["name"], "n": v["n"], "hit": v["hit"],
                        "rate_pct": round(100*v["hit"]/v["n"],2)} for g,v in sorted(grp.items())},
       "misses": miss, "false_positives": fp,
       "latency_p95_ms": round(sorted(lat)[int(len(lat)*0.95)],3)}
json.dump(res, io.open(os.path.join(ROOT,"results","metrics_holdout.json"),"w",encoding="utf-8"),
          ensure_ascii=False, indent=2)
print(f"\n{'═'*60}\n  留出集（检测器冻结后编写，仅运行一次）\n{'═'*60}")
print(f"  注入拦截率   {res['block_rate_pct']:6.2f}%   ({TP}/{len(adv)})")
print(f"  正常误拦率   {res['false_block_rate_pct']:6.2f}%   ({FP}/{len(ben)})")
print(f"  精确率       {res['precision_pct']:6.2f}%      F1 {res['f1_pct']:.2f}%")
print("\n  ── 分组 ──")
for g,v in res["by_group"].items():
    tag = "拦截率" if g != "H5" else "误拦率"
    print(f"   {g} {v['name']:<18} {tag} {v['rate_pct']:6.2f}%  ({v['hit']}/{v['n']})")
print(f"\n  ── 漏报 {len(miss)} 条 ──")
for m in miss: print(f"   {m['id']} [{m['group']}] score={m['score']}  {m['text'][:84]}")
if fp:
    print(f"\n  ── 误拦 {len(fp)} 条 ──")
    for f in fp: print(f"   {f['id']} {f['families']} score={f['score']}  {f['text'][:84]}")

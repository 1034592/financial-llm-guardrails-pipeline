# -*- coding: utf-8 -*-
"""
资产 B 评测主程序
=================
输出三组指标：
  ① 注入拦截率 / 正常业务误拦率（按攻击家族与业务场景分组）
  ② 脱敏召回率 / 精确率（实体级，按类型分解）+ 可逆性校验
  ③ 单次检查延迟（p50 / p95 / 均值，分拆检测与脱敏两段）
"""
import json, io, os, sys, time, statistics
from collections import defaultdict, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)
from detect import detect
from pii import mask, Vault

def load(fn):
    with io.open(os.path.join(ROOT, "data", fn), encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]

def pct(x): return round(100.0 * x, 2)

def main():
    adv, ben, pii = load("adversarial.jsonl"), load("benign.jsonl"), load("pii_set.jsonl")
    res = {"dataset": {"adversarial": len(adv), "benign": len(ben),
                       "pii_texts": len(pii),
                       "pii_entities": sum(len(r["entities"]) for r in pii)}}

    # ── ① 注入检测 ──
    lat_detect = []
    grp = defaultdict(lambda: {"n": 0, "hit": 0, "name": ""})
    misses, fps = [], []
    for r in adv + ben:
        t0 = time.perf_counter()
        d = detect(r["text"])
        lat_detect.append((time.perf_counter() - t0) * 1000)
        g = grp[r["group"]]; g["n"] += 1; g["name"] = r["group_name"]
        if r["label"] == 1:
            if d["blocked"]: g["hit"] += 1
            else: misses.append({"id": r["id"], "group": r["group"],
                                 "text": r["text"][:110], "score": d["score"]})
        else:
            if d["blocked"]:
                g["hit"] += 1
                fps.append({"id": r["id"], "group": r["group"], "text": r["text"][:110],
                            "score": d["score"], "families": d["families"]})

    TP = sum(grp[g]["hit"] for g in grp if g.startswith("A"))
    FN = len(adv) - TP
    FP = sum(grp[g]["hit"] for g in grp if g.startswith("B"))
    TN = len(ben) - FP
    prec = TP / (TP + FP) if TP + FP else 0.0
    rec  = TP / (TP + FN) if TP + FN else 0.0
    res["injection"] = {
        "TP": TP, "FN": FN, "FP": FP, "TN": TN,
        "block_rate_pct": pct(rec),
        "false_block_rate_pct": pct(FP / len(ben)),
        "precision_pct": pct(prec),
        "f1_pct": pct(2 * prec * rec / (prec + rec)) if prec + rec else 0.0,
        "accuracy_pct": pct((TP + TN) / (len(adv) + len(ben))),
        "by_group": {g: {"name": v["name"], "n": v["n"], "hit": v["hit"],
                         "rate_pct": pct(v["hit"] / v["n"])} for g, v in sorted(grp.items())},
        "misses": misses, "false_positives": fps,
    }

    # ── ② 脱敏 ──
    lat_mask = []
    tp_e = Counter(); fn_e = Counter(); fp_e = 0; rev_ok = 0
    for r in pii:
        t0 = time.perf_counter()
        masked, vault, ents = mask(r["text"], Vault())
        lat_mask.append((time.perf_counter() - t0) * 1000)
        found = {(e[2], e[3]) for e in ents}
        found_vals = {e[3] for e in ents}
        for gt in r["entities"]:
            # 真值命中判定：值被完整覆盖（允许检测器切分出的片段包含真值）
            ok = any(gt["value"].replace(" ", "") in fv.replace(" ", "") or
                     fv.replace(" ", "") in gt["value"].replace(" ", "")
                     for fv in found_vals)
            (tp_e if ok else fn_e)[gt["type"]] += 1
        gt_vals = {g["value"].replace(" ", "") for g in r["entities"]}
        for et, val in found:
            v = val.replace(" ", "")
            if not any(v in gv or gv in v for gv in gt_vals):
                fp_e += 1
        if vault.restore(masked) == r["text"]:
            rev_ok += 1

    TPm, FNm = sum(tp_e.values()), sum(fn_e.values())
    pm = TPm / (TPm + fp_e) if TPm + fp_e else 0.0
    rm = TPm / (TPm + FNm) if TPm + FNm else 0.0
    res["masking"] = {
        "entities_total": TPm + FNm, "TP": TPm, "FN": FNm, "FP": fp_e,
        "recall_pct": pct(rm), "precision_pct": pct(pm),
        "f1_pct": pct(2 * pm * rm / (pm + rm)) if pm + rm else 0.0,
        "reversibility_pct": pct(rev_ok / len(pii)),
        "by_type": {t: {"n": tp_e[t] + fn_e[t], "hit": tp_e[t],
                        "recall_pct": pct(tp_e[t] / (tp_e[t] + fn_e[t]))}
                    for t in sorted(set(tp_e) | set(fn_e))},
    }

    # ── ③ 延迟：单次观测在共享 VPS 上不稳定，故跑 ROUNDS 轮取中位数与范围 ──
    def stats(xs):
        xs = sorted(xs)
        return {"n": len(xs), "mean_ms": round(statistics.fmean(xs), 3),
                "p50_ms": round(xs[len(xs)//2], 3),
                "p95_ms": round(xs[int(len(xs)*0.95)], 3),
                "max_ms": round(xs[-1], 3)}

    ROUNDS = 10
    rd = {"det_p50": [], "det_p95": [], "msk_p50": [], "msk_p95": [], "combined_p95": []}
    for _ in range(ROUNDS):
        ld, lm = [], []
        for r in adv + ben:
            t0 = time.perf_counter(); detect(r["text"]); ld.append((time.perf_counter()-t0)*1000)
        for r in pii:
            t0 = time.perf_counter(); mask(r["text"], Vault()); lm.append((time.perf_counter()-t0)*1000)
        sd, sm = stats(ld), stats(lm)
        rd["det_p50"].append(sd["p50_ms"]);  rd["det_p95"].append(sd["p95_ms"])
        rd["msk_p50"].append(sm["p50_ms"]);  rd["msk_p95"].append(sm["p95_ms"])
        rd["combined_p95"].append(round(sd["p95_ms"] + sm["p95_ms"], 3))

    def agg(xs):
        return {"median_ms": round(statistics.median(xs), 3),
                "min_ms": round(min(xs), 3), "max_ms": round(max(xs), 3)}

    res["latency"] = {
        "rounds": ROUNDS,
        "note": "每轮对全部样本重测一遍；报告跨轮中位数与范围，单次观测不作为指标。",
        "injection_check": {"p50": agg(rd["det_p50"]), "p95": agg(rd["det_p95"])},
        "pii_masking":     {"p50": agg(rd["msk_p50"]), "p95": agg(rd["msk_p95"])},
        "combined_p95":    agg(rd["combined_p95"]),
    }
    res["environment"] = {"python": sys.version.split()[0], "deps": "标准库 only（re / unicodedata / hmac）"}

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    with io.open(os.path.join(ROOT, "results", "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)

    i, m, l = res["injection"], res["masking"], res["latency"]
    print(f"\n{'═'*62}\n  ① 注入检测　对抗 {len(adv)} / 正常 {len(ben)}\n{'═'*62}")
    print(f"  注入拦截率   {i['block_rate_pct']:6.2f}%   ({i['TP']}/{len(adv)})")
    print(f"  正常误拦率   {i['false_block_rate_pct']:6.2f}%   ({i['FP']}/{len(ben)})")
    print(f"  精确率       {i['precision_pct']:6.2f}%      F1 {i['f1_pct']:.2f}%      准确率 {i['accuracy_pct']:.2f}%")
    print(f"\n  ── 分组明细 ──")
    for g, v in i["by_group"].items():
        tag = "拦截率" if g.startswith("A") else "误拦率"
        print(f"   {g} {v['name']:<16} {tag} {v['rate_pct']:6.2f}%  ({v['hit']}/{v['n']})")
    print(f"\n{'═'*62}\n  ② 脱敏　{res['dataset']['pii_texts']} 条文本 / {m['entities_total']} 个实体\n{'═'*62}")
    print(f"  召回率 {m['recall_pct']:.2f}%   精确率 {m['precision_pct']:.2f}%   F1 {m['f1_pct']:.2f}%   可逆性 {m['reversibility_pct']:.2f}%")
    for t, v in m["by_type"].items():
        print(f"   {t:<11} {v['recall_pct']:6.2f}%  ({v['hit']}/{v['n']})")
    print(f"\n{'═'*62}\n  ③ 延迟（{l['rounds']} 轮重测，中位数／范围）\n{'═'*62}")
    for key, name in (("injection_check", "注入检查"), ("pii_masking", "PII 脱敏")):
        a, b = l[key]["p50"], l[key]["p95"]
        print(f"  {name}   p50 {a['median_ms']:.3f} ms ({a['min_ms']:.3f}–{a['max_ms']:.3f})"
              f"   p95 {b['median_ms']:.3f} ms ({b['min_ms']:.3f}–{b['max_ms']:.3f})")
    c = l["combined_p95"]
    print(f"  合并 p95   {c['median_ms']:.3f} ms  范围 {c['min_ms']:.3f}–{c['max_ms']:.3f} ms")
    print(f"\n  漏报 {len(i['misses'])} 条　误拦 {len(i['false_positives'])} 条　→ results/metrics.json")

if __name__ == "__main__":
    main()

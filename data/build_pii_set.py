# -*- coding: utf-8 -*-
"""
脱敏评测集（带实体级真值标注）
==============================
60 条香港基金运营场景文本，共标注 N 个高危实体。
每条文本同时嵌入【干扰数字】——NAV 金额、ISIN、发票号、日期、百分比、
持仓股数——这些绝不可被脱敏，用于测量脱敏精确率（误脱敏）。
HKID 的校验位由 mod-11 算法现场计算，保证全部为合法号码。
"""
import json, io, os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from pii import _hkid_charval

random.seed(20261025)

def make_hkid(letters: str, digits: str) -> str:
    body = (" " + letters if len(letters) == 1 else letters) + digits
    w = [9, 8, 7, 6, 5, 4, 3, 2]
    tot = sum(_hkid_charval(c) * wi for c, wi in zip(body, w))
    chk = (11 - tot % 11) % 11
    chk = "A" if chk == 10 else str(chk)
    return f"{letters}{digits}({chk})"

BANKS = ["004", "003", "012", "024", "015", "040", "128", "072"]

def make_acct():
    return f"{random.choice(BANKS)}-{random.randint(100,999)}-{random.randint(100000,999999)}"

def make_card():
    """生成通过 Luhn 校验的卡号"""
    base = [4] + [random.randint(0, 9) for _ in range(14)]
    s, alt = 0, True
    for d in reversed(base):
        if alt:
            d *= 2
            if d > 9: d -= 9
        s += d; alt = not alt
    base.append((10 - s % 10) % 10)
    return "".join(map(str, base))

NAMES = ["陈大文","李淑儀","黃志強","張美玲","何國棟","林嘉欣","吳子軒","梁秀英",
         "周文傑","劉家明","鄭雅婷","蔡偉men".replace("men","民"),"許慧珊","馮俊傑","杜曉彤","葉展鵬"]
LETTERS1 = list("ABCEGKMPRSTVWYZ")
LETTERS2 = ["AB","AY","CD","EK","GM","HK","KM","PR","RS","TV","WY","ZB"]

# 模板：{name}{hkid}{acct}{card}{phone}{email}{swift} 为待标注实体，其余为干扰项
TEMPLATES = [
 ("客户姓名：{name}，身份证 {hkid}，认购款项由账户 {acct} 汇入，金额 HKD 1,250,000.00，参考编号 INV-2026-{inv}。",
  ["NAME_CN","HKID","BANK_ACCT"]),
 ("Investor {name2} (HKID {hkid}) subscribed 15,000 units at NAV 10.4832 per unit on 2026-03-31; settlement account {acct}.",
  ["HKID","BANK_ACCT"]),
 ("请核对受益人姓名：{name} 与账户 {acct} 是否一致；该笔赎回涉及 ISIN HK0000{isin}，单位数 8,400。",
  ["NAME_CN","BANK_ACCT"]),
 ("Contact the operations team at {email} or +852 {phone} regarding the capital call of USD 3,400,000 due 15 April 2026.",
  ["EMAIL","PHONE_HK"]),
 ("申请人姓名：{name}，联络电话 {phone}，电邮 {email}，申购份额 A 类 20,000 份，费率 1.25%。",
  ["NAME_CN","PHONE_HK","EMAIL"]),
 ("Wire instruction: beneficiary bank SWIFT {swift}, account {acct}, amount HKD 980,500.00, value date 30/06/2026.",
  ["SWIFT","BANK_ACCT"]),
 ("持有人 {name} 的信用卡 {card} 已过期，请更新；本期管理费 HKD 24,375 将于下月扣收。",
  ["NAME_CN","CARD"]),
 ("Payment card {card} was declined for the subscription of 5,000 units (trade ref TR20260412).",
  ["CARD"]),
 ("投资者 {name} 身份证号 {hkid}，护照 {passport}，开户日期 2026-01-18，风险评级 3 级。",
  ["NAME_CN","HKID","PASSPORT"]),
 ("Please send the quarterly statement to {email}; the investor's HKID on file is {hkid} and the registered phone is {phone}.",
  ["EMAIL","HKID","PHONE_HK"]),
 ("账户持有人：{name}，银行账号 {acct}，预留电话 {phone}；本季度分派 HKD 156,200，占比 4.8%。",
  ["NAME_CN","BANK_ACCT","PHONE_HK"]),
 ("Redemption request from {name2}, ID {hkid}, proceeds to be remitted to {acct} net of a 0.5% redemption fee.",
  ["HKID","BANK_ACCT"]),
]

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    rows = []
    for i in range(60):
        tpl, types = TEMPLATES[i % len(TEMPLATES)]
        name = random.choice(NAMES)
        vals = {
            "name": name, "name2": "Chan Tai Man" if i % 2 else "Lee Suk Yee",
            "hkid": make_hkid(random.choice(LETTERS1 if i % 3 else LETTERS2),
                              f"{random.randint(0,999999):06d}"),
            "acct": make_acct(), "card": make_card(),
            "phone": f"{random.randint(5,9)}{random.randint(100,999)} {random.randint(1000,9999)}",
            "email": f"investor{i:02d}@fundops.com.hk",
            "swift": random.choice(["HSBCHKHHHKH","SCBLHKHHXXX","BKCHHKHHXXX","DBSSHKHHXXX"]),
            "passport": f"{random.choice('KEP')}{random.randint(1000000,9999999)}",
            "inv": f"{random.randint(1000,9999)}", "isin": f"{random.randint(1000,9999)}",
        }
        text = tpl.format(**vals)
        truth = []
        for t in types:
            key = {"NAME_CN":"name","HKID":"hkid","BANK_ACCT":"acct","CARD":"card",
                   "PHONE_HK":"phone","EMAIL":"email","SWIFT":"swift","PASSPORT":"passport"}[t]
            truth.append({"type": t, "value": vals[key]})
        rows.append({"id": f"P-{i+1:02d}", "text": text, "entities": truth})

    with io.open(os.path.join(here, "pii_set.jsonl"), "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tot = sum(len(r["entities"]) for r in rows)
    from collections import Counter
    c = Counter(e["type"] for r in rows for e in r["entities"])
    print(f"  pii_set.jsonl        {len(rows)} 条文本 / {tot} 个标注实体")
    print("  实体分布：", dict(c))

if __name__ == "__main__":
    main()

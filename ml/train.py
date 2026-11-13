import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from ml.features import FEATURE_NAMES, URL_FEATURE_NAMES, extract_features_df, normalize_host

DATA_PATH = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
ML_DIR = ROOT / "ml"
SEED = 42


def load_data():
    df = pd.read_csv(DATA_PATH, usecols=["URL", "label"], encoding="utf-8-sig")
    stats = {"raw_rows": len(df)}
    df = df.dropna(subset=["URL", "label"])
    df["URL"] = df["URL"].astype(str).str.strip()
    df = df[df["URL"] != ""]
    df["label"] = 1 - df["label"].astype(int)
    stats["dup_urls"] = int(df["URL"].duplicated().sum())
    df = df.drop_duplicates("URL").reset_index(drop=True)
    stats["rows"] = len(df)
    return df, stats


def show_label_examples(df):
    print("Проверка меток (1 = фишинг, 0 = легитимный):")
    for label in (1, 0):
        sample = df[df["label"] == label]["URL"].sample(3, random_state=SEED).tolist()
        for url in sample:
            print(f"  {label}  {url[:90]}")


def format_skew(df):
    u = df["URL"].str.lower()
    rest = u.str.replace(r"^https?://", "", regex=True)
    checks = {
        "схема https://": u.str.startswith("https://"),
        "префикс https://www.": u.str.startswith("https://www."),
        "есть путь": ~rest.str.match(r"^[^/?#]+/?$"),
        "есть query (?)": u.str.contains("?", regex=False),
        "слэш в конце": u.str.endswith("/"),
    }
    rows = []
    for name, mask in checks.items():
        grouped = mask.groupby(df["label"]).mean()
        rows.append((name, grouped.get(1, 0.0), grouped.get(0, 0.0)))
    lengths = u.str.len().groupby(df["label"]).median()
    return rows, lengths


def build_host_dataset(df):
    hosts = df.assign(host=df["URL"].map(normalize_host))
    hosts = hosts[hosts["host"] != ""]
    per_host = hosts.groupby("host")["label"].nunique()
    conflicts = set(per_host[per_host > 1].index)
    hosts = hosts[~hosts["host"].isin(conflicts)]
    hosts = hosts.drop_duplicates("host").reset_index(drop=True)
    return hosts, len(conflicts)


def make_models():
    return {
        "LogisticRegression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=2000, random_state=SEED)
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=300, n_jobs=-1, random_state=SEED
        ),
        "XGBoost": make_xgb(),
    }


def make_xgb():
    return XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.9,
        colsample_bytree=0.9,
        tree_method="hist",
        eval_metric="logloss",
        n_jobs=-1,
        random_state=SEED,
    )


def evaluate(model, X_test, y_test):
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
    return {
        "Accuracy": accuracy_score(y_test, pred),
        "Precision": precision_score(y_test, pred, zero_division=0),
        "Recall": recall_score(y_test, pred, zero_division=0),
        "F1": f1_score(y_test, pred, zero_division=0),
        "ROC-AUC": roc_auc_score(y_test, proba),
        "FPR": fp / (fp + tn) if fp + tn else 0.0,
        "cm": (int(tn), int(fp), int(fn), int(tp)),
    }


def split(X, y):
    return train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)


def leakage_baseline(df):
    X = extract_features_df(df["URL"], include_url_features=True)
    X_train, X_test, y_train, y_test = split(X, df["label"])
    model = make_xgb().fit(X_train, y_train)
    result = evaluate(model, X_test, y_test)
    gain = model.get_booster().get_score(importance_type="gain")
    top = sorted(gain.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return result, top


def md_table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def write_report(stats, skew, lengths, host_stats, results, importance, leak, leak_top):
    metric_keys = ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC", "FPR"]
    metric_rows = [[name] + [f"{r[k]:.4f}" for k in metric_keys] for name, r in results.items()]
    cm_rows = [[name, *r["cm"]] for name, r in results.items()]
    skew_rows = [[name, f"{p:.1%}", f"{l:.1%}"] for name, p, l in skew]
    skew_rows.append(["медиана длины URL", int(lengths.get(1, 0)), int(lengths.get(0, 0))])
    imp_rows = [[i + 1, name, f"{g:.1f}"] for i, (name, g) in enumerate(importance)]
    leak_rows = [[name, f"{g:.1f}"] for name, g in leak_top]

    text = f"""# Метрики ML-модели (этап 1)

## Данные

- Источник: PhiUSIIL Phishing URL Dataset, строк в CSV: {stats['raw_rows']}.
- Метки в исходнике: 1 = легитимный, 0 = фишинг. Приведены к виду **1 = фишинг, 0 = легитимный**.
- Удалено дублей URL: {stats['dup_urls']}, осталось {stats['rows']} URL.

## Проверка перекоса по формату URL

| Признак | Фишинг | Легитимные |
|---|---|---|
""" + "\n".join("| " + " | ".join(str(c) for c in r) + " |" for r in skew_rows) + f"""

**Вывод:** перекос есть. Все легитимные URL в датасете имеют вид `https://www.<домен>` без пути, query и слэша в конце.
Признаки схемы, пути, query и длины полного URL отделяют классы по артефакту сбора данных, а не по признакам фишинга.
В браузере такая модель считала бы фишингом любую легитимную страницу с путём.

**Решение:** URL нормализуется до хоста (без схемы, `www.`, порта, пути, query, фрагмента, в нижнем регистре, IDN в punycode).
Модель обучается только на признаках хоста. Признаки уровня URL (`{', '.join(URL_FEATURE_NAMES)}`)
в модель не входят. Они считаются функцией `url_features()` и будут использованы в бэкенде как пояснения и правила.

Набор для обучения строится по уникальным хостам, чтобы один хост не попадал и в train, и в test:
- уникальных хостов: {host_stats['hosts']} (фишинг {host_stats['phish']}, легитимные {host_stats['legit']});
- исключено хостов с противоречивыми метками: {host_stats['conflicts']}.

## Демонстрация утечки (модель НЕ используется)

XGBoost на сырых URL с признаками хоста и признаками уровня URL:
F1 = {leak['F1']:.4f}, ROC-AUC = {leak['ROC-AUC']:.4f}, FPR = {leak['FPR']:.4f}.

Главные признаки по gain:

{md_table(["Признак", "Gain"], leak_rows)}

Высокое качество здесь объясняется перекосом формата, а не способностью модели распознавать фишинг.

## Итоговые модели (признаки хоста, stratified 80/20, random_state={SEED})

Признаки ({len(FEATURE_NAMES)}): {', '.join(FEATURE_NAMES)}.

{md_table(["Модель"] + metric_keys, metric_rows)}

### Матрицы ошибок (test)

{md_table(["Модель", "TN", "FP", "FN", "TP"], cm_rows)}

### Важность признаков XGBoost (gain, топ-10)

{md_table(["#", "Признак", "Gain"], imp_rows)}

Сохранённая модель: `ml/model.json`, порядок признаков: `ml/feature_names.json`.
"""
    (ML_DIR / "metrics.md").write_text(text, encoding="utf-8")


def main():
    t0 = time.time()
    df, stats = load_data()
    print(f"URL после очистки: {stats['rows']} (дублей удалено {stats['dup_urls']})")
    print("Баланс классов:", df["label"].value_counts().to_dict())
    show_label_examples(df)

    skew, lengths = format_skew(df)
    print("\nПерекос формата (фишинг / легитимные):")
    for name, p, l in skew:
        print(f"  {name:<22} {p:7.1%} {l:7.1%}")

    hosts, conflicts = build_host_dataset(df)
    host_stats = {
        "hosts": len(hosts),
        "phish": int((hosts["label"] == 1).sum()),
        "legit": int((hosts["label"] == 0).sum()),
        "conflicts": conflicts,
    }
    print(f"\nУникальных хостов: {host_stats}")

    X = extract_features_df(hosts["host"])
    X_train, X_test, y_train, y_test = split(X, hosts["label"])

    results = {}
    trained = {}
    for name, model in make_models().items():
        t = time.time()
        model.fit(X_train, y_train)
        results[name] = evaluate(model, X_test, y_test)
        trained[name] = model
        r = results[name]
        print(
            f"{name:<20} F1={r['F1']:.4f} P={r['Precision']:.4f} R={r['Recall']:.4f} "
            f"AUC={r['ROC-AUC']:.4f} FPR={r['FPR']:.4f} ({time.time() - t:.1f} c)"
        )

    xgb = trained["XGBoost"]
    gain = xgb.get_booster().get_score(importance_type="gain")
    importance = sorted(gain.items(), key=lambda kv: kv[1], reverse=True)[:10]
    print("\nТоп-10 признаков XGBoost (gain):")
    for name, g in importance:
        print(f"  {name:<22} {g:.1f}")

    xgb.save_model(ML_DIR / "model.json")
    (ML_DIR / "feature_names.json").write_text(json.dumps(FEATURE_NAMES, indent=2), encoding="utf-8")

    print("\nДемонстрация утечки на сырых URL...")
    leak, leak_top = leakage_baseline(df)
    print(f"  F1={leak['F1']:.4f} AUC={leak['ROC-AUC']:.4f} FPR={leak['FPR']:.4f}")

    write_report(stats, skew, lengths, host_stats, results, importance, leak, leak_top)
    print(f"\nГотово за {time.time() - t0:.1f} c: ml/model.json, ml/feature_names.json, ml/metrics.md")


if __name__ == "__main__":
    main()

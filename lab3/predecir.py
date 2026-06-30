#!/usr/bin/env python3
"""
predecir.py
Lab 3 - Tarea 3.4: Script de predicción con modelo exportado
Uso: python3 predecir.py nuevo_trafico.csv
"""
import sys
import pandas as pd
import numpy as np
import joblib

if len(sys.argv) < 2:
    print("Uso: python3 predecir.py <archivo_csv>")
    sys.exit(1)

CSV_PATH = sys.argv[1]
MODEL_PATH = "modelo_anomalias.pkl"
SCALER_PATH = "scaler.pkl"

features = ["bytes_sent", "bytes_recv", "duration_sec", "packets",
            "ratio_bytes", "bytes_por_segundo"]

print(f"Cargando modelo desde {MODEL_PATH}...")
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

print(f"Cargando datos desde {CSV_PATH}...")
df = pd.read_csv(CSV_PATH)

df["ratio_bytes"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
df["bytes_por_segundo"] = df["bytes_sent"] / (df["duration_sec"] + 0.001)

X = scaler.transform(df[features])
scores = model.decision_function(X)
preds = model.predict(X)

df["anomaly_score"] = scores
df["prediccion"] = preds

anomalias = df[preds == -1]
print(f"\nTotal registros analizados: {len(df)}")
print(f"Anomalías detectadas: {len(anomalias)}")
print(f"\n{'='*60}")
print("REGISTROS CLASIFICADOS COMO ANOMALÍA:")
print(f"{'='*60}")
print(anomalias[["src_ip","dst_ip","dst_port","protocol",
                  "bytes_sent","duration_sec","anomaly_score"]].to_string())

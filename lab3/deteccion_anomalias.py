#!/usr/bin/env python3
"""
deteccion_anomalias.py
Lab 3 - Detección de Anomalías con Isolation Forest
Tarea 3.1: EDA y preprocesamiento
Tarea 3.2: Entrenamiento y métricas
Tarea 3.3: Interpretación y umbral dinámico
Tarea 3.4: Exportación del modelo
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import joblib
import warnings
warnings.filterwarnings("ignore")

# ============================================================
# TAREA 3.1 — EDA y preprocesamiento
# ============================================================
print("=" * 60)
print("TAREA 3.1 — Exploración y Preprocesamiento")
print("=" * 60)

df = pd.read_csv("network_traffic.csv")
print(f"\nShape: {df.shape}")
print(f"\nColumnas: {list(df.columns)}")
print(f"\nEstadísticas descriptivas:")
print(df.describe())

print(f"\nValores nulos por columna:")
print(df.isnull().sum())

print(f"\nDistribución de etiquetas:")
print(df["label"].value_counts())

# Tratar valores nulos
df = df.dropna()
print(f"\nShape tras eliminar nulos: {df.shape}")

# Eliminar atípicos extremos (percentil 99.9)
for col in ["bytes_sent", "duration_sec"]:
    p999 = df[col].quantile(0.999)
    df = df[df[col] <= p999]
print(f"Shape tras eliminar atípicos extremos: {df.shape}")

# Feature engineering
df["ratio_bytes"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
df["bytes_por_segundo"] = df["bytes_sent"] / (df["duration_sec"] + 0.001)
print(f"\nNuevas features creadas: ratio_bytes, bytes_por_segundo")

# Visualizaciones EDA
fig, axes = plt.subplots(1, 2, figsize=(12, 5))
axes[0].hist(df["bytes_sent"], bins=50, color="steelblue", edgecolor="black")
axes[0].set_title("Distribución de bytes_sent")
axes[0].set_xlabel("bytes_sent")
axes[0].set_ylabel("Frecuencia")

axes[1].hist(df["duration_sec"], bins=50, color="coral", edgecolor="black")
axes[1].set_title("Distribución de duration_sec")
axes[1].set_xlabel("duration_sec")
axes[1].set_ylabel("Frecuencia")

plt.tight_layout()
plt.savefig("evidencias/SCR-3.1_eda.png", dpi=150)
plt.close()
print("\nGráfica EDA guardada: evidencias/SCR-3.1_eda.png")

# Normalización
features = ["bytes_sent", "bytes_recv", "duration_sec", "packets",
            "ratio_bytes", "bytes_por_segundo"]
scaler = StandardScaler()
X = scaler.fit_transform(df[features])
y_true = (df["label"] == "anomaly").astype(int).values
print(f"\nFeatures usadas: {features}")
print(f"X shape: {X.shape}")

# ============================================================
# TAREA 3.2 — Entrenamiento del modelo
# ============================================================
print("\n" + "=" * 60)
print("TAREA 3.2 — Entrenamiento del Modelo")
print("=" * 60)

model = IsolationForest(
    contamination=0.05,
    n_estimators=100,
    random_state=42
)
model.fit(X)

# Predicciones: -1 anomalia, 1 normal
y_pred_raw = model.predict(X)
y_pred = (y_pred_raw == -1).astype(int)  # 1=anomalia, 0=normal

precision = precision_score(y_true, y_pred, zero_division=0)
recall = recall_score(y_true, y_pred, zero_division=0)
f1 = f1_score(y_true, y_pred, zero_division=0)
cm = confusion_matrix(y_true, y_pred)

print(f"\nMétricas de evaluación:")
print(f"  Precision : {precision:.4f}")
print(f"  Recall    : {recall:.4f}")
print(f"  F1-Score  : {f1:.4f}")
print(f"\nMatriz de confusión:")
print(cm)

# Gráfica matriz de confusión
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Normal", "Anomalía"],
            yticklabels=["Normal", "Anomalía"])
plt.title("Matriz de Confusión — Isolation Forest")
plt.ylabel("Real")
plt.xlabel("Predicho")
plt.tight_layout()
plt.savefig("evidencias/SCR-3.2_metricas.png", dpi=150)
plt.close()
print("\nGráfica métricas guardada: evidencias/SCR-3.2_metricas.png")

# ============================================================
# TAREA 3.3 — Interpretación y umbral dinámico
# ============================================================
print("\n" + "=" * 60)
print("TAREA 3.3 — Interpretación y Umbral Dinámico")
print("=" * 60)

scores = model.decision_function(X)

# Curva umbral vs F1
thresholds = np.linspace(scores.min(), scores.max(), 200)
f1_scores = []
for t in thresholds:
    y_t = (scores < t).astype(int)
    f1_scores.append(f1_score(y_true, y_t, zero_division=0))

best_idx = np.argmax(f1_scores)
best_threshold = thresholds[best_idx]
best_f1 = f1_scores[best_idx]
print(f"\nUmbral óptimo: {best_threshold:.4f}")
print(f"Mejor F1-Score: {best_f1:.4f}")

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

axes[0].plot(thresholds, f1_scores, color="green")
axes[0].axvline(best_threshold, color="red", linestyle="--",
                label=f"Umbral óptimo={best_threshold:.3f}")
axes[0].set_title("Curva Umbral vs F1-Score")
axes[0].set_xlabel("Umbral")
axes[0].set_ylabel("F1-Score")
axes[0].legend()

axes[1].scatter(range(len(scores)), scores, c=(scores < best_threshold),
                cmap="coolwarm", alpha=0.5, s=5)
axes[1].axhline(best_threshold, color="red", linestyle="--",
                label=f"Umbral={best_threshold:.3f}")
axes[1].set_title("Anomaly Score por registro")
axes[1].set_xlabel("Índice")
axes[1].set_ylabel("Decision Score")
axes[1].legend()

plt.tight_layout()
plt.savefig("evidencias/SCR-3.3_umbral_f1.png", dpi=150)
plt.close()
print("Gráfica umbral-F1 guardada: evidencias/SCR-3.3_umbral_f1.png")

# Top 10 más anómalos
df_result = df.copy()
df_result["anomaly_score"] = scores
df_result["prediccion"] = y_pred
top10 = df_result.nsmallest(10, "anomaly_score")
print(f"\nTop 10 registros más anómalos:")
print(top10[["src_ip", "dst_ip", "dst_port", "protocol",
             "bytes_sent", "bytes_recv", "duration_sec",
             "packets", "anomaly_score", "label"]].to_string())

print("""
Análisis de amenazas (Top 10):
- Registros con bytes_sent extremadamente altos pueden indicar exfiltración de datos.
- Conexiones con duration_sec muy elevada sugieren backdoors o tunneling persistente.
- Combinación de alto bytes_por_segundo + puerto inusual puede ser C2 (Command & Control).
- Protocolos ICMP con alto volumen sugieren ICMP tunneling para evasión de firewall.
""")

# ============================================================
# TAREA 3.4 — Exportación del modelo
# ============================================================
print("=" * 60)
print("TAREA 3.4 — Exportación del Modelo")
print("=" * 60)

joblib.dump(model, "modelo_anomalias.pkl")
joblib.dump(scaler, "scaler.pkl")
print("\nModelo exportado: modelo_anomalias.pkl")
print("Scaler exportado: scaler.pkl")
print("\n✓ Lab 3 completado exitosamente.")

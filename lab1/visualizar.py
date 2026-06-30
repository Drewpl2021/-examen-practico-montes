#!/usr/bin/env python3
import re
from collections import Counter
from datetime import datetime
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

SSH_PATTERN = re.compile(r"Failed password for (?:invalid user )?\S+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
WEB_PATTERN = re.compile(r'\d{1,3}(?:\.\d{1,3}){3} \S+ \S+ \[(?P<datetime>[^\]]+)\] ".+? HTTP/\S+" (?P<status>\d{3})')
DATE_FORMAT = "%d/%b/%Y:%H:%M:%S"
DIR = "graficas"

def grafica1():
    intentos = Counter()
    with open("auth.log", errors="ignore") as f:
        for l in f:
            if "Failed password" in l:
                m = SSH_PATTERN.search(l)
                if m:
                    intentos[m.group("ip")] += 1
    top10 = intentos.most_common(10)
    ips, counts = zip(*top10)
    plt.figure(figsize=(10, 6))
    sns.barplot(x=list(counts), y=list(ips), color="crimson")
    plt.title("Top 10 IPs con más intentos fallidos SSH")
    plt.xlabel("Número de intentos")
    plt.ylabel("IP")
    plt.tight_layout()
    plt.savefig(f"{DIR}/top10_ssh.png", dpi=150)
    plt.close()
    print("Guardado: top10_ssh.png")

def parsear_web():
    rows = []
    with open("access.log", errors="ignore") as f:
        for l in f:
            m = WEB_PATTERN.search(l)
            if not m:
                continue
            try:
                dt = datetime.strptime(m.group("datetime").split(" ")[0], DATE_FORMAT)
                rows.append({"datetime": dt, "status": int(m.group("status"))})
            except:
                pass
    return pd.DataFrame(rows)

def grafica2(df):
    df["hora"] = df["datetime"].dt.floor("h")
    conteo = df.groupby("hora").size()
    plt.figure(figsize=(12, 5))
    conteo.plot(kind="line", marker="o", color="steelblue")
    plt.title("Peticiones HTTP por hora")
    plt.xlabel("Hora")
    plt.ylabel("Peticiones")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f"{DIR}/timeline_http.png", dpi=150)
    plt.close()
    print("Guardado: timeline_http.png")

def grafica3(df):
    df["hora"] = df["datetime"].dt.hour
    df2 = df[df["status"].isin([200, 301, 404, 500])]
    tabla = pd.crosstab(df2["hora"], df2["status"]).reindex(columns=[200,301,404,500], fill_value=0)
    plt.figure(figsize=(10, 7))
    sns.heatmap(tabla, annot=True, fmt="d", cmap="YlOrRd")
    plt.title("Peticiones por hora y código de respuesta")
    plt.xlabel("Código")
    plt.ylabel("Hora")
    plt.tight_layout()
    plt.savefig(f"{DIR}/heatmap_http.png", dpi=150)
    plt.close()
    print("Guardado: heatmap_http.png")

grafica1()
df = parsear_web()
grafica2(df)
grafica3(df)
print("\n✓ Las 3 gráficas generadas en graficas/")

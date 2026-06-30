#!/usr/bin/env python3
import re, json
from collections import Counter
from datetime import datetime

LOG_PATH = "lab1/auth.log"
OUTPUT_PATH = "lab1/reporte_ssh.json"
UMBRAL = 50

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def main():
    intentos = Counter()
    with open(LOG_PATH, "r", errors="ignore") as f:
        for linea in f:
            if "Failed password" not in linea:
                continue
            m = PATTERN.search(linea)
            if m:
                intentos[m.group("ip")] += 1

    top10 = intentos.most_common(10)
    print("=" * 60)
    print("TOP 10 IPs con más intentos fallidos SSH")
    print("=" * 60)
    for i, (ip, count) in enumerate(top10, 1):
        print(f"{i:2d}. {ip:<15} -> {count} intentos")
    print("=" * 60)

    ips_alerta = []
    for ip, count in intentos.items():
        if count > UMBRAL:
            print(f"[ALERTA] IP: {ip} — {count} intentos fallidos — Posible ataque de fuerza bruta")
            ips_alerta.append(ip)

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": sum(intentos.values()),
        "ips_sospechosas": [
            {"ip": ip, "intentos": count, "alerta": ip in ips_alerta}
            for ip, count in top10
        ],
    }
    with open(OUTPUT_PATH, "w") as f:
        json.dump(reporte, f, indent=2)
    print(f"\nReporte exportado a {OUTPUT_PATH}")

if __name__ == "__main__":
    main()

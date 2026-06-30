#!/usr/bin/env python3
import re, json
from collections import defaultdict
from datetime import datetime

LOG_PATH = "lab1/access.log"
OUTPUT_PATH = "lab1/reporte_web.json"

LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>.+?) HTTP/\S+" (?P<status>\d{3})'
)
DATE_FORMAT = "%d/%b/%Y:%H:%M:%S"
SQLI_PATTERNS = ["UNION", "SELECT", "--", "OR 1=1", "'"]

def parsear():
    registros = []
    with open(LOG_PATH, "r", errors="ignore") as f:
        for linea in f:
            m = LOG_PATTERN.search(linea)
            if not m:
                continue
            try:
                dt = datetime.strptime(m.group("datetime").split(" ")[0], DATE_FORMAT)
            except ValueError:
                continue
            registros.append({"ip": m.group("ip"), "datetime": dt,
                               "path": m.group("path"), "status": int(m.group("status"))})
    return registros

def detectar_escaneo(registros):
    por_ip = defaultdict(list)
    for r in registros:
        por_ip[r["ip"]].append(r)
    sospechosas = []
    for ip, evs in por_ip.items():
        evs.sort(key=lambda x: x["datetime"])
        ventana = []
        for ev in evs:
            ventana.append(ev)
            ventana = [e for e in ventana if (ev["datetime"] - e["datetime"]).total_seconds() <= 60]
            if len({e["path"] for e in ventana}) > 20:
                sospechosas.append({"ip": ip, "rutas_distintas": len({e["path"] for e in ventana})})
                print(f"[ALERTA] Escaneo de directorios desde {ip}")
                break
    return sospechosas

def detectar_errores(registros):
    errores = defaultdict(lambda: {"4xx": 0, "5xx": 0})
    for r in registros:
        if 400 <= r["status"] < 500:
            errores[r["ip"]]["4xx"] += 1
        elif 500 <= r["status"] < 600:
            errores[r["ip"]]["5xx"] += 1
    return dict(errores)

def detectar_sqli(registros):
    hallazgos = []
    for r in registros:
        patrones = [p for p in SQLI_PATTERNS if p.upper() in r["path"].upper()]
        if patrones:
            hallazgos.append({"ip": r["ip"], "path": r["path"], "patrones": patrones})
            print(f"[ALERTA] SQLi desde {r['ip']} -> {r['path']}")
    return hallazgos

def main():
    registros = parsear()
    print(f"Total líneas parseadas: {len(registros)}\n")
    print("--- Escaneo de directorios ---")
    escaneos = detectar_escaneo(registros)
    print("\n--- Códigos 4xx/5xx por IP ---")
    errores = detectar_errores(registros)
    for ip, v in errores.items():
        print(f"{ip}: 4xx={v['4xx']} 5xx={v['5xx']}")
    print("\n--- SQL Injection ---")
    sqli = detectar_sqli(registros)
    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_peticiones": len(registros),
        "escaneo_directorios": escaneos,
        "errores_por_ip": errores,
        "intentos_sqli": sqli,
    }
    with open(OUTPUT_PATH, "w") as f:
        json.dump(reporte, f, indent=2)
    print(f"\nReporte exportado a {OUTPUT_PATH}")

if __name__ == "__main__":
    main()

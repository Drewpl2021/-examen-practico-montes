# Examen Práctico Final — Seguridad Informática

**Unidad IV — Monitoreo de Seguridad, SIEM e Inteligencia Artificial**

---

**Estudiante:** Andrés Lino Montes Mamani
**Escuela Profesional:** Ingeniería de Sistemas
**Ciclo:** IX
**Curso:** Seguridad Informática
**Modalidad:** Laboratorio / Evaluación Práctica

---

## Tabla de Contenidos

1. [Descripción General](#1-descripción-general)
2. [Entorno de Trabajo](#2-entorno-de-trabajo)
3. [Versiones de Herramientas Instaladas](#3-versiones-de-herramientas-instaladas)
4. [Configuración del Entorno](#4-configuración-del-entorno)
5. [Estructura del Repositorio](#5-estructura-del-repositorio)
6. [Laboratorio 1 — Análisis Forense de Logs](#6-laboratorio-1--análisis-forense-de-logs)
7. [Laboratorio 2 — Reglas de Correlación en Wazuh](#7-laboratorio-2--reglas-de-correlación-en-wazuh)
8. [Laboratorio 3 — Detección de Anomalías con ML](#8-laboratorio-3--detección-de-anomalías-con-ml)
9. [Reproducción Completa](#9-reproducción-completa)

---

## 1. Descripción General

Este repositorio contiene el desarrollo completo del Examen Práctico Final del curso de
Seguridad Informática. El trabajo abarca tres laboratorios que cubren el ciclo completo de
monitoreo de seguridad: análisis forense de logs con Python, creación de reglas de correlación
en un SIEM (Wazuh), y detección de anomalías de red mediante Machine Learning (Isolation Forest).

El objetivo es implementar un sistema de monitoreo de seguridad que detecte ataques de fuerza
bruta, escaneo de directorios, inyección SQL y tráfico de red anómalo, integrando técnicas de
análisis de eventos en tiempo real e inteligencia artificial.

---

## 2. Entorno de Trabajo

El examen se desarrolló íntegramente en un entorno local virtualizado:

| Componente | Detalle |
|------------|---------|
| Host | Windows (24 GB RAM) |
| Virtualizador | Oracle VirtualBox |
| Máquina Virtual | Ubuntu 26.04 LTS (Resolute) |
| IP de la VM | 192.168.0.112 |
| Acceso | SSH desde el host hacia la VM |
| Recursos asignados | Suficientes para ejecutar Wazuh All-in-One + Python + ML |

El acceso a la VM se realiza por SSH:

```bash
ssh andres@192.168.0.112
```

---

## 3. Versiones de Herramientas Instaladas

| Herramienta | Versión |
|-------------|---------|
| Sistema Operativo | Ubuntu 26.04 LTS (Resolute) |
| Python | 3.14.4 |
| Wazuh Manager | v4.12.0 (rc1) — server |
| pandas | 3.0.3 |
| numpy | 2.5.0 |
| scikit-learn | 1.7.2 |
| matplotlib | 3.11.0 |
| seaborn | 0.13.2 |
| joblib | 1.5.2 |
| IP de la VM | 192.168.0.112 |

Comandos usados para verificar versiones:

```bash
lsb_release -a
python3 --version
sudo /var/ossec/bin/wazuh-control info
pip list | grep -iE "pandas|numpy|scikit|matplotlib|seaborn|joblib"
```

---

## 4. Configuración del Entorno

### 4.1 Dependencias de Python

> **Nota:** Ubuntu 26.04 incluye Python 3.14, para el cual scikit-learn aún no
> distribuye wheels en PyPI. Por ello scikit-learn se instaló desde los repositorios
> de apt (`python3-sklearn`), que provee la versión 1.7.2 compilada.

```bash
sudo apt update
sudo apt install -y python3-pip unzip libxml2-utils
sudo apt install -y python3-sklearn python3-sklearn-lib
pip install pandas numpy matplotlib seaborn joblib --break-system-packages
```

### 4.2 Instalación de Wazuh (All-in-One)

```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

Verificación del servicio:

```bash
sudo systemctl status wazuh-manager
```

### 4.3 Configuración de Git

```bash
git config --global user.name "Andres Lino Montes Mamani"
git config --global user.email "linoplas0@gmail.com"
```

---

## 5. Estructura del Repositorio

```
examen-practico-montes/
├── README.md                          ← Documentación general
├── lab1/                              ← Análisis Forense de Logs
│   ├── analizar_ssh.py
│   ├── analizar_web.py
│   ├── visualizar.py
│   ├── auth.log
│   ├── access.log
│   ├── reporte_ssh.json              ← Generado al ejecutar
│   ├── reporte_web.json              ← Generado al ejecutar
│   ├── graficas/
│   │   ├── top10_ssh.png
│   │   ├── timeline_http.png
│   │   └── heatmap_http.png
│   └── evidencias/                   ← Screenshots Lab 1
├── lab2/                             ← Reglas Wazuh
│   ├── local_rules_ssh.xml
│   ├── local_rules_exfil.xml
│   ├── simular_bruteforce.sh
│   └── evidencias/                   ← Screenshots Lab 2
└── lab3/                             ← Modelo ML
    ├── deteccion_anomalias.py
    ├── predecir.py
    ├── network_traffic.csv
    ├── modelo_anomalias.pkl
    ├── scaler.pkl
    └── evidencias/                   ← Screenshots Lab 3
```

---

## 6. Laboratorio 1 — Análisis Forense de Logs

Análisis forense de logs de autenticación SSH (`auth.log`, 500 líneas) y acceso web Apache
(`access.log`, 1000 líneas) mediante scripts de Python.

### 6.1 `analizar_ssh.py` (Tarea 1.1)

Parsea `auth.log`, identifica intentos fallidos de autenticación (`Failed password`),
cuenta por IP de origen, genera un ranking de las 10 IPs con más intentos, emite alertas
de fuerza bruta (umbral > 50 intentos) y exporta `reporte_ssh.json`.

```bash
cd lab1
python3 analizar_ssh.py
```

**Resultados clave:** se detectaron 2 IPs con ataque de fuerza bruta
(`45.33.32.156` con 120 intentos y `193.32.162.55` con 58 intentos).

### 6.2 `analizar_web.py` (Tarea 1.2)

Parsea `access.log` en formato Combined Log Format, detecta escaneo de directorios
(>20 rutas distintas en <60s), agrupa códigos 4xx/5xx por IP, y detecta intentos de
SQL Injection (patrones `UNION`, `SELECT`, `--`, `OR 1=1`, `'`). Exporta `reporte_web.json`.

```bash
python3 analizar_web.py
```

**Resultados clave:** se detectaron intentos de SQLi desde `193.32.162.55`
(herramienta sqlmap identificada en los patrones).

### 6.3 `visualizar.py` (Tarea 1.3)

Genera 3 gráficas: barras del Top 10 IPs SSH, línea de tiempo de peticiones HTTP por hora,
y heatmap de peticiones por hora y código de respuesta.

```bash
python3 visualizar.py
```

Salida en `lab1/graficas/`: `top10_ssh.png`, `timeline_http.png`, `heatmap_http.png`.

---

## 7. Laboratorio 2 — Reglas de Correlación en Wazuh

Creación de reglas de correlación personalizadas en Wazuh, ubicadas en
`/var/ossec/etc/rules/local_rules.xml`.

### 7.1 Regla Brute Force SSH (Tarea 2.1)

| Campo | Valor |
|-------|-------|
| Rule ID | 100001 / 100002 |
| Nivel | 10 |
| Grupo | `authentication_failures, brute_force` |
| Lógica | 10+ fallos SSH desde la misma IP en 60s (regla 100001), con respaldo sobre la detección nativa 5763 (regla 100002) |

La regla 100001 usa `frequency=10` y `timeframe=60` sobre la regla base 5760. La regla 100002
se monta sobre la detección nativa de Wazuh (5763) para garantizar el disparo en entornos
journald.

### 7.2 Regla Exfiltración de Datos (Tarea 2.2)

| Campo | Valor |
|-------|-------|
| Rule ID | 100010 / 100011 |
| Nivel | 14 (crítico) |
| Grupo | `data_exfiltration, high_risk` |
| Lógica | Correlación de login exitoso fuera de horario (22:00–06:00) seguido de transferencia masiva de datos |

### 7.3 Prueba y Evidencia (Tarea 2.3)

```bash
# Validar XML
sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml && echo OK

# Reiniciar Wazuh
sudo systemctl restart wazuh-manager

# Simular ataque
sudo bash lab2/simular_bruteforce.sh

# Verificar disparo de la regla (mediante wazuh-logtest)
sudo /var/ossec/bin/wazuh-logtest
```

La regla 100002 disparó correctamente mostrando:
`Ataque de fuerza bruta SSH confirmado desde 45.33.32.156` (nivel 10, grupo brute_force).

---

## 8. Laboratorio 3 — Detección de Anomalías con ML

Modelo de detección de anomalías de tráfico de red mediante Isolation Forest, sobre el
dataset `network_traffic.csv` (10 000 registros de 30 días).

### 8.1 EDA y Preprocesamiento (Tarea 3.1)

Carga del dataset, estadísticas descriptivas, histogramas de `bytes_sent` y `duration_sec`,
tratamiento de nulos y atípicos extremos (percentil 99.9), y feature engineering:
`ratio_bytes` y `bytes_por_segundo`. Normalización con `StandardScaler`.

### 8.2 Entrenamiento (Tarea 3.2)

```python
IsolationForest(contamination=0.05, n_estimators=100, random_state=42)
```

Se calculan Precision, Recall, F1-Score y matriz de confusión usando la columna `label`
solo para validación (no para entrenamiento).

### 8.3 Interpretación y Umbral Dinámico (Tarea 3.3)

Gráfica del `decision_function` por registro, curva umbral vs F1-Score para identificar el
umbral óptimo, y listado de los Top 10 registros más anómalos con análisis de amenazas.

### 8.4 Exportación (Tarea 3.4)

El modelo se serializa con joblib (`modelo_anomalias.pkl`). El script `predecir.py` carga el
modelo y clasifica nuevos archivos CSV:

```bash
cd lab3
python3 deteccion_anomalias.py      # entrena y evalúa
python3 predecir.py network_traffic.csv   # predice anomalías
```

---

## 9. Reproducción Completa

```bash
# 1. Clonar el repositorio
git clone git@github.com:Drewpl2021/-examen-practico-montes.git
cd -examen-practico-montes

# 2. Lab 1
cd lab1
python3 analizar_ssh.py
python3 analizar_web.py
python3 visualizar.py
cd ..

# 3. Lab 2 (requiere Wazuh instalado)
sudo cp lab2/local_rules_ssh.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo bash lab2/simular_bruteforce.sh

# 4. Lab 3
cd lab3
python3 deteccion_anomalias.py
python3 predecir.py network_traffic.csv
```

---

_Examen Práctico Final — Seguridad Informática — Ingeniería de Sistemas — Ciclo IX_

<h1 align="center">🔐 SSL/TLS Verifier</h1>
<p align="center">
  Herramienta CLI desarrollada en Bash para analizar la configuración TLS de uno o varios servidores,
  identificar hallazgos de seguridad y generar reportes HTML con recomendaciones de remediación.
</p>

---

## 📌 Descripción

**SSL/TLS Verifier** es una herramienta orientada al análisis defensivo de configuraciones TLS en servidores expuestos a red. Permite evaluar uno o varios dominios o direcciones IP, identificar versiones habilitadas del protocolo, detectar configuraciones inseguras o no recomendadas y presentar un resumen claro del nivel de exposición del servidor analizado.

La solución fue desarrollada como un MVP en entorno CLI, utilizando **Bash**, **testssl.sh** y **nmap**, con el objetivo de transformar resultados técnicos en información comprensible y accionable para el usuario.

---

## 🎯 Objetivo

Diseñar una aplicación CLI end-to-end que permita analizar uno o varios dominios o direcciones IP, verificando las versiones de TLS habilitadas, la presencia de protocolos obsoletos, configuraciones inseguras o no recomendadas y el estado general del servidor evaluado. La herramienta busca entregar al usuario una visión clara, simplificada y comprensible del nivel de seguridad de la conexión establecida con el servidor.

---

## ⚙️ Características

- Análisis de uno o varios dominios o direcciones IP
- Validación básica de entrada
- Verificación de protocolos SSL/TLS detectados
- Identificación de configuraciones inseguras o no recomendadas
- Clasificación de hallazgos por severidad
- Generación de reporte final en HTML
- Almacenamiento de evidencia técnica en archivos de salida
- Resumen ejecutivo por cada objetivo analizado

---

## 🛠️ Tecnologías utilizadas

- **Bash**
- **testssl.sh**
- **nmap**
- **HTML**

---

## 📂 Estructura del proyecto

```bash
.
├── main.sh
├── testssl.sh
├── outputs/
└── README.md

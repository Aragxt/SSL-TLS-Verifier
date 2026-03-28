## 🚀 Instrucciones de uso

Para ejecutar **SSL/TLS Verifier**, el usuario debe contar con un entorno Linux o compatible con **Bash**, así como con las herramientas `nmap` y `testssl.sh` disponibles en el mismo directorio del script o correctamente instaladas en el sistema.

La ejecución se realiza desde consola mediante el comando correspondiente al script principal. Una vez iniciado, el programa solicita al usuario el ingreso de uno o varios objetivos de análisis.

---

### 📥 Formato de entrada

La herramienta permite ingresar:

- una dirección IP individual, por ejemplo: `8.8.8.8`
- un dominio individual, por ejemplo: `google.com`
- varias direcciones IP y/o dominios separadas por comas, por ejemplo: `8.8.8.8, google.com, github.com`

---

### ✅ Validaciones realizadas

Antes de ejecutar el análisis, la herramienta valida que cada entrada corresponda a:

- una dirección IPv4 válida, o
- un dominio con formato correcto

Si algún valor ingresado no cumple con el formato esperado, este se omite y se notifica al usuario mediante un mensaje de advertencia.

---

### 🔍 Proceso de análisis

Por cada objetivo válido, la herramienta realiza automáticamente:

1. escaneo del puerto 443 y enumeración básica con `nmap`
2. análisis de configuración SSL/TLS con `testssl.sh`
3. identificación de protocolos habilitados
4. detección de configuraciones inseguras o no recomendadas
5. clasificación de hallazgos por severidad
6. generación de un reporte final en formato HTML

---

### 📂 Archivos generados

Por cada servidor analizado, el programa genera en la carpeta `outputs` los siguientes archivos:

- resultado de `nmap`
- resultado de `testssl.sh`
- reporte final en formato HTML

---

### ⚠️ Consideraciones

- El análisis se realiza sobre servicios accesibles desde la red donde se ejecuta la herramienta.
- Si el host no responde, el puerto está cerrado o se presenta timeout, el análisis puede generar resultados incompletos.
- La herramienta está orientada al análisis defensivo de configuración TLS y no a la explotación de vulnerabilidades.


________________________________________
# Verificador SSL/TLS - MVP Bash

Herramienta de línea de comandos desarrollada en **Bash** para analizar la configuración SSL/TLS de uno o varios servidores web, detectar protocolos heredados, configuraciones inseguras y generar reportes técnicos en consola y en HTML.

## Objetivo

Este proyecto fue diseñado como un MVP para apoyar el análisis defensivo de servicios expuestos a internet, permitiendo:

- Analizar una o varias IPs o dominios
- Detectar versiones SSL/TLS habilitadas
- Identificar protocolos heredados o inseguros
- Detectar configuraciones inseguras o no recomendadas
- Clasificar hallazgos por severidad
- Generar recomendaciones de remediación
- Generar un reporte HTML por objetivo analizado

## Características

- Ingreso de uno o varios objetivos separados por coma
- Validación básica de IP y dominio
- Verificación de resolución DNS para dominios
- Verificación de accesibilidad del puerto 443
- Ejecución de análisis con:
  - `testssl.sh`
  - `nmap`
- Identificación de protocolos:
  - SSLv2
  - SSLv3
  - TLS 1.0
  - TLS 1.1
  - TLS 1.2
  - TLS 1.3
- Detección de hallazgos como:
  - protocolos heredados
  - NULL ciphers
  - anonymous ciphers
  - CBC heredado
  - certificado autofirmado
  - SAN ausente
  - hostname mismatch
  - clave RSA débil
  - ausencia de HSTS
  - posible BREACH
  - exposición de banner
- Resumen ejecutivo por objetivo
- Reporte HTML individual por host

## Estructura esperada del proyecto

```bash
.
├── tls_audit.sh
├── testssl.sh
└── outputs/

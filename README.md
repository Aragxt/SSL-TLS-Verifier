## 🚀 Instrucciones de uso

Para ejecutar **SSL/TLS Verifier**, el usuario debe contar con un entorno Linux o compatible con **Bash**, así como con las herramientas `nmap` y `testssl.sh` disponibles en el mismo directorio del script o correctamente instaladas en el sistema.

La ejecución se realiza desde consola mediante el comando correspondiente al script principal. Una vez iniciado, el programa solicita al usuario el ingreso de uno o varios objetivos de análisis.

---
### 📦 Dependencias

Para ejecutar **SSL/TLS Verifier**, el usuario debe contar con las siguientes dependencias instaladas en el sistema:

- `bash`
- `nmap`
- `testssl.sh`

Además, `testssl.sh` debe encontrarse en el mismo directorio del script principal o estar disponible para su ejecución desde la terminal.

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

### 🔍 Caracteristicas

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


```bash
.
├── tls_audit.sh
├── testssl.sh
└── outputs/

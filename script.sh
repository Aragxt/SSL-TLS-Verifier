#!/usr/bin/env bash

# ==========================================
# Verificador SSL/TLS - MVP Bash
# ==========================================

clear

# Arrays para almacenar hallazgos
declare -a FINDING_SEVERITY
declare -a FINDING_TITLE
declare -a FINDING_EVIDENCE
declare -a FINDING_RECOMMENDATION


# Variables globales de resumen
OVERALL_RISK="SIN DATOS"
COUNT_CRITICO=0
COUNT_ALTO=0
COUNT_MEDIO=0
COUNT_BAJO=0

# Variables para protocolos
PROTO_SSLV2_STATUS=""
PROTO_SSLV2_LINE=""
PROTO_SSLV3_STATUS=""
PROTO_SSLV3_LINE=""
PROTO_TLS10_STATUS=""
PROTO_TLS10_LINE=""
PROTO_TLS11_STATUS=""
PROTO_TLS11_LINE=""
PROTO_TLS12_STATUS=""
PROTO_TLS12_LINE=""
PROTO_TLS13_STATUS=""
PROTO_TLS13_LINE=""
LEGACY_PROTOCOLS=""
SECURE_PROTOCOLS=""
RECOMMENDED_MISSING=""
PROTOCOL_POSTURE=""

# Estado del objetivo
TARGET_STATUS="PENDIENTE"
TARGET_STATUS_DETAIL=""

OUTDIR="outputs"
mkdir -p "$OUTDIR"

print_separator() {
    echo "----------------------------------------------"
}

show_banner() {
    clear
    echo "=============================================="
    echo "   Hola, bienvenida/o al Verificador SSL/TLS"
    echo "=============================================="
    echo "Este software analiza IPs o dominios y evalúa"
    echo "la configuración básica de TLS usando:"
    echo " - testssl.sh"
    echo " - nmap"
    echo "=============================================="
    echo
}

is_valid_ipv4() {
    local ip="$1"
    local IFS=.
    local -a octets

    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    read -r -a octets <<< "$ip"

    for octet in "${octets[@]}"; do
        if (( octet < 0 || octet > 255 )); then
            return 1
        fi
    done

    return 0
}

is_valid_domain() {
    local domain="$1"

    [[ ${#domain} -le 253 ]] || return 1
    [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$ ]] || return 1

    return 0
}

sanitize_target_name() {
    echo "$1" | sed 's/[^a-zA-Z0-9._-]/_/g'
}

reset_findings() {
    FINDING_SEVERITY=()
    FINDING_TITLE=()
    FINDING_EVIDENCE=()
    FINDING_RECOMMENDATION=()

    OVERALL_RISK="SIN DATOS"
    COUNT_CRITICO=0
    COUNT_ALTO=0
    COUNT_MEDIO=0
    COUNT_BAJO=0

    PROTO_SSLV2_STATUS=""
    PROTO_SSLV2_LINE=""
    PROTO_SSLV3_STATUS=""
    PROTO_SSLV3_LINE=""
    PROTO_TLS10_STATUS=""
    PROTO_TLS10_LINE=""
    PROTO_TLS11_STATUS=""
    PROTO_TLS11_LINE=""
    PROTO_TLS12_STATUS=""
    PROTO_TLS12_LINE=""
    PROTO_TLS13_STATUS=""
    PROTO_TLS13_LINE=""

    TARGET_STATUS="PENDIENTE"
    TARGET_STATUS_DETAIL=""
    
    LEGACY_PROTOCOLS=""
    SECURE_PROTOCOLS=""
    RECOMMENDED_MISSING=""
    PROTOCOL_POSTURE=""
}

get_targets() {
    read -rp "Por favor ingresa una o varias IPs/dominios separados por coma: " TARGET_INPUT

    if [[ -z "$TARGET_INPUT" ]]; then
        echo "[ERROR] No ingresaste ningún objetivo."
        exit 1
    fi

    IFS=',' read -r -a RAW_TARGETS <<< "$TARGET_INPUT"
    TARGETS=()

    for raw in "${RAW_TARGETS[@]}"; do
        target=$(echo "$raw" | xargs)

        if [[ -z "$target" ]]; then
            continue
        fi

        if is_valid_ipv4 "$target" || is_valid_domain "$target"; then
            TARGETS+=("$target")
        else
            echo "[WARN] Objetivo inválido omitido: $target"
        fi
    done

    if [[ ${#TARGETS[@]} -eq 0 ]]; then
        echo "[ERROR] No se encontraron IPs o dominios válidos para analizar."
        exit 1
    fi
}

is_resolvable() {
    local target="$1"

    if is_valid_domain "$target"; then
        getent hosts "$target" >/dev/null 2>&1
        return $?
    fi

    return 0
}

check_port_443() {
    local target="$1"
    local port_check_file="$OUTDIR/portcheck_$(sanitize_target_name "$target").txt"

    timeout 30s nmap -Pn -p 443 "$target" -oN "$port_check_file" >/dev/null 2>&1
    local rc=$?

    if [[ $rc -eq 124 ]]; then
        TARGET_STATUS="TIMEOUT"
        TARGET_STATUS_DETAIL="Timeout al verificar el puerto 443."
        return 1
    fi

    if grep -q "443/tcp open" "$port_check_file"; then
        return 0
    fi

    if grep -q "443/tcp closed" "$port_check_file"; then
        TARGET_STATUS="PORT_CLOSED"
        TARGET_STATUS_DETAIL="El puerto 443 está cerrado."
        return 1
    fi

    if grep -q "443/tcp filtered" "$port_check_file"; then
        TARGET_STATUS="FILTERED"
        TARGET_STATUS_DETAIL="El puerto 443 está filtrado o inaccesible."
        return 1
    fi

    TARGET_STATUS="CONNECTION_ERROR"
    TARGET_STATUS_DETAIL="No fue posible determinar el estado del puerto 443."
    return 1
}

run_nmap_with_timeout() {
    timeout 90s nmap -Pn -p 443 --script ssl-enum-ciphers,ssl-cert "$TARGET" -oN "$NMAP_OUT" >/dev/null 2>&1
    local rc=$?

    if [[ $rc -eq 124 ]]; then
        TARGET_STATUS="TIMEOUT"
        TARGET_STATUS_DETAIL="Timeout durante la ejecución de nmap."
        return 1
    elif [[ $rc -ne 0 ]]; then
        TARGET_STATUS="SCAN_ERROR"
        TARGET_STATUS_DETAIL="Error al ejecutar nmap."
        return 1
    fi

    return 0
}

run_testssl_with_timeout() {
    timeout 300s ./testssl.sh --color 0 "$TARGET" > "$TESTSSL_OUT" 2>&1
    local rc=$?

    if [[ $rc -eq 124 ]]; then
        TARGET_STATUS="TIMEOUT"
        TARGET_STATUS_DETAIL="Timeout durante la ejecución de testssl.sh."
        return 1
    elif [[ $rc -ne 0 ]]; then
        TARGET_STATUS="SCAN_ERROR"
        TARGET_STATUS_DETAIL="Error al ejecutar testssl.sh."
        return 1
    fi

    return 0
}

check_protocol_version() {
    local label="$1"
    local pattern="$2"
    local line
    local status

    line=$(grep -E "$pattern" "$TESTSSL_OUT" | head -n 1 | sed 's/^[[:space:]]*//')

    if [[ -z "$line" ]]; then
        status="NO ENCONTRADA"
    elif echo "$line" | grep -q "not offered"; then
        status="DESACTIVADA"
    elif echo "$line" | grep -q "offered"; then
        status="ACTIVADA"
    else
        status="ESTADO NO DETERMINADO"
    fi

    echo "$label: $status"
    echo "   -> $line"

    case "$label" in
        "SSLv2")
            PROTO_SSLV2_STATUS="$status"
            PROTO_SSLV2_LINE="$line"
            ;;
        "SSLv3")
            PROTO_SSLV3_STATUS="$status"
            PROTO_SSLV3_LINE="$line"
            ;;
        "TLS 1.0")
            PROTO_TLS10_STATUS="$status"
            PROTO_TLS10_LINE="$line"
            ;;
        "TLS 1.1")
            PROTO_TLS11_STATUS="$status"
            PROTO_TLS11_LINE="$line"
            ;;
        "TLS 1.2")
            PROTO_TLS12_STATUS="$status"
            PROTO_TLS12_LINE="$line"
            ;;
        "TLS 1.3")
            PROTO_TLS13_STATUS="$status"
            PROTO_TLS13_LINE="$line"
            ;;
    esac
}

add_finding() {
    local severity="$1"
    local title="$2"
    local evidence="$3"
    local recommendation="$4"

    FINDING_SEVERITY+=("$severity")
    FINDING_TITLE+=("$title")
    FINDING_EVIDENCE+=("$evidence")
    FINDING_RECOMMENDATION+=("$recommendation")
}

check_insecure_configuration() {
    local pattern="$1"
    local severity="$2"
    local title="$3"
    local recommendation="$4"
    local line

    line=$(grep -E "$pattern" "$TESTSSL_OUT" | head -n 1 | sed 's/^[[:space:]]*//')

    if [[ -n "$line" ]]; then
        add_finding "$severity" "$title" "$line" "$recommendation"
    fi
}

parse_findings() {
    check_insecure_configuration "^ TLS 1[[:space:]].*offered" \
    "CRITICO" \
    "TLS 1.0 habilitado" \
    "Deshabilitar TLS 1.0 y restringir el servicio a TLS 1.2 o superior."

    check_insecure_configuration "^ TLS 1\.1.*offered" \
    "CRITICO" \
    "TLS 1.1 habilitado" \
    "Deshabilitar TLS 1.1 y restringir el servicio a TLS 1.2 o superior."

    check_insecure_configuration "^ NULL ciphers .*offered" \
    "CRITICO" \
    "NULL ciphers habilitados" \
    "Deshabilitar suites sin cifrado real."

    check_insecure_configuration "^ Anonymous NULL Ciphers .*offered" \
    "CRITICO" \
    "Cifrados anónimos habilitados" \
    "Deshabilitar suites anónimas sin autenticación."

    check_insecure_configuration "Obsoleted CBC ciphers.*offered" \
    "ALTO" \
    "Cifrados CBC obsoletos habilitados" \
    "Priorizar suites AEAD modernas y reducir el uso de CBC heredado."

    check_insecure_configuration "Has server cipher order.*no \(NOT ok\)" \
    "MEDIO" \
    "El servidor no define preferencia de cifrados" \
    "Configurar el orden de preferencia de cifrados del lado del servidor."

    check_insecure_configuration "subjectAltName \(SAN\).*missing" \
    "CRITICO" \
    "SAN ausente en el certificado" \
    "Incluir subjectAltName válido en el certificado."

    check_insecure_configuration "Trust \(hostname\).*does not match supplied URI" \
    "CRITICO" \
    "El certificado no coincide con el host analizado" \
    "Asegurar coincidencia entre el certificado y el dominio o IP esperada."

    check_insecure_configuration "Chain of trust.*self signed" \
    "CRITICO" \
    "Certificado autofirmado" \
    "Reemplazar por un certificado emitido por una CA confiable."

    check_insecure_configuration "Server key size.*RSA[[:space:]]+1024" \
    "ALTO" \
    "Clave RSA débil" \
    "Migrar a una clave RSA de al menos 2048 bits."

    check_insecure_configuration "OCSP URI.*NOT ok" \
    "MEDIO" \
    "No se encontró mecanismo de revocación del certificado" \
    "Configurar OCSP o CRL para permitir verificación de revocación."

    check_insecure_configuration "Strict Transport Security.*not offered" \
    "MEDIO" \
    "HSTS no configurado" \
    "Habilitar HSTS para forzar el uso de HTTPS."

    check_insecure_configuration "BREACH.*potentially NOT ok" \
    "MEDIO" \
    "Posible exposición a BREACH por compresión HTTP" \
    "Revisar el uso de compresión HTTP en respuestas con información sensible."

    check_insecure_configuration "TLS 1\.3.*not offered" \
    "BAJO" \
    "TLS 1.3 no está habilitado" \
    "Evaluar compatibilidad para habilitar TLS 1.3."

    check_insecure_configuration "Server banner.*nginx/" \
    "BAJO" \
    "Banner del servidor expuesto" \
    "Minimizar la exposición de banners para reducir información visible."
}

count_findings_by_severity() {
    COUNT_CRITICO=0
    COUNT_ALTO=0
    COUNT_MEDIO=0
    COUNT_BAJO=0

    for severity in "${FINDING_SEVERITY[@]}"; do
        case "$severity" in
            CRITICO) ((COUNT_CRITICO++)) ;;
            ALTO)    ((COUNT_ALTO++)) ;;
            MEDIO)   ((COUNT_MEDIO++)) ;;
            BAJO)    ((COUNT_BAJO++)) ;;
        esac
    done
}

calculate_overall_risk() {
    count_findings_by_severity

    if (( COUNT_CRITICO > 0 )); then
        OVERALL_RISK="CRITICO"
    elif (( COUNT_ALTO > 0 )); then
        OVERALL_RISK="ALTO"
    elif (( COUNT_MEDIO > 0 )); then
        OVERALL_RISK="MEDIO"
    elif (( COUNT_BAJO > 0 )); then
        OVERALL_RISK="BAJO"
    else
        OVERALL_RISK="SIN HALLAZGOS"
    fi
}

evaluate_protocol_posture() {
    LEGACY_PROTOCOLS=""
    SECURE_PROTOCOLS=""
    RECOMMENDED_MISSING=""
    PROTOCOL_POSTURE=""

    [[ "$PROTO_SSLV2_STATUS" == "ACTIVADA" ]] && LEGACY_PROTOCOLS+="SSLv2, "
    [[ "$PROTO_SSLV3_STATUS" == "ACTIVADA" ]] && LEGACY_PROTOCOLS+="SSLv3, "
    [[ "$PROTO_TLS10_STATUS" == "ACTIVADA" ]] && LEGACY_PROTOCOLS+="TLS 1.0, "
    [[ "$PROTO_TLS11_STATUS" == "ACTIVADA" ]] && LEGACY_PROTOCOLS+="TLS 1.1, "

    [[ "$PROTO_TLS12_STATUS" == "ACTIVADA" ]] && SECURE_PROTOCOLS+="TLS 1.2, "
    [[ "$PROTO_TLS13_STATUS" == "ACTIVADA" ]] && SECURE_PROTOCOLS+="TLS 1.3, "

    [[ "$PROTO_TLS13_STATUS" != "ACTIVADA" ]] && RECOMMENDED_MISSING+="TLS 1.3, "

    LEGACY_PROTOCOLS="${LEGACY_PROTOCOLS%, }"
    SECURE_PROTOCOLS="${SECURE_PROTOCOLS%, }"
    RECOMMENDED_MISSING="${RECOMMENDED_MISSING%, }"

    if [[ -n "$LEGACY_PROTOCOLS" && -n "$SECURE_PROTOCOLS" ]]; then
        PROTOCOL_POSTURE="Configuración heredada con soporte moderno parcial"
    elif [[ -n "$LEGACY_PROTOCOLS" && -z "$SECURE_PROTOCOLS" ]]; then
        PROTOCOL_POSTURE="Configuración heredada no recomendada"
    elif [[ -z "$LEGACY_PROTOCOLS" && -n "$SECURE_PROTOCOLS" ]]; then
        PROTOCOL_POSTURE="Configuración moderna"
    else
        PROTOCOL_POSTURE="No fue posible determinar la postura del protocolo"
    fi
}

print_executive_summary() {
    echo
    echo "=============================================="
    echo "Resumen ejecutivo"
    echo "=============================================="
    echo "Servidor analizado: $TARGET"
    echo "Estado del objetivo: $TARGET_STATUS"
    echo "Detalle: $TARGET_STATUS_DETAIL"
    echo "Total hallazgos detectados: ${#FINDING_TITLE[@]}"
    echo "Críticos: $COUNT_CRITICO"
    echo "Altos:    $COUNT_ALTO"
    echo "Medios:   $COUNT_MEDIO"
    echo "Bajos:    $COUNT_BAJO"
    echo "Nivel de exposición general: $OVERALL_RISK"
    echo
}

print_findings() {
    echo
    echo "=============================================="
    echo "Hallazgos inseguros detectados"
    echo "=============================================="

    if [[ ${#FINDING_TITLE[@]} -eq 0 ]]; then
        echo "[OK] No se detectaron hallazgos inseguros con las reglas actuales."
        return
    fi

    for i in "${!FINDING_TITLE[@]}"; do
        echo "[$((i+1))] ${FINDING_TITLE[$i]}"
        echo "    Severidad: ${FINDING_SEVERITY[$i]}"
        echo "    Evidencia: ${FINDING_EVIDENCE[$i]}"
        echo "    Recomendación: ${FINDING_RECOMMENDATION[$i]}"
        echo
    done
}

html_escape() {
    sed -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&#39;/g"
}

severity_color() {
    case "$1" in
        CRITICO) echo "#b91c1c" ;;
        ALTO)    echo "#ea580c" ;;
        MEDIO)   echo "#ca8a04" ;;
        BAJO)    echo "#2563eb" ;;
        *)       echo "#374151" ;;
    esac
}

generate_html_report() {
    local risk_color
    risk_color=$(severity_color "$OVERALL_RISK")

    {
        echo "<!DOCTYPE html>"
        echo "<html lang=\"es\">"
        echo "<head>"
        echo "  <meta charset=\"UTF-8\">"
        echo "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        echo "  <title>Reporte SSL/TLS - $TARGET</title>"
        echo "  <style>"
        echo "    body { font-family: Arial, sans-serif; margin: 30px; background: #f8fafc; color: #1f2937; }"
        echo "    h1, h2 { color: #111827; }"
        echo "    .card { background: white; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }"
        echo "    .risk { font-weight: bold; color: $risk_color; }"
        echo "    table { width: 100%; border-collapse: collapse; margin-top: 10px; }"
        echo "    th, td { border: 1px solid #d1d5db; padding: 10px; text-align: left; vertical-align: top; }"
        echo "    th { background: #e5e7eb; }"
        echo "    .sev { font-weight: bold; color: white; padding: 4px 8px; border-radius: 6px; display: inline-block; }"
        echo "    .critico { background: #b91c1c; }"
        echo "    .alto { background: #ea580c; }"
        echo "    .medio { background: #ca8a04; }"
        echo "    .bajo { background: #2563eb; }"
        echo "  </style>"
        echo "</head>"
        echo "<body>"

        echo "  <div class=\"card\">"
        echo "    <h1>Reporte de Análisis SSL/TLS</h1>"
        echo "    <p><strong>Servidor analizado:</strong> $(printf '%s' "$TARGET" | html_escape)</p>"
        echo "    <p><strong>Estado del objetivo:</strong> $(printf '%s' "$TARGET_STATUS" | html_escape)</p>"
        echo "    <p><strong>Detalle:</strong> $(printf '%s' "$TARGET_STATUS_DETAIL" | html_escape)</p>"
        echo "    <p><strong>Nivel de exposición general:</strong> <span class=\"risk\">$(printf '%s' "$OVERALL_RISK" | html_escape)</span></p>"
        echo "  </div>"

        echo "  <div class=\"card\">"
        echo "    <h2>Resumen ejecutivo</h2>"
        echo "    <ul>"
        echo "      <li>Total hallazgos detectados: ${#FINDING_TITLE[@]}</li>"
        echo "      <li>Críticos: $COUNT_CRITICO</li>"
        echo "      <li>Altos: $COUNT_ALTO</li>"
        echo "      <li>Medios: $COUNT_MEDIO</li>"
        echo "      <li>Bajos: $COUNT_BAJO</li>"
        echo "    </ul>"
        echo "  </div>"

        echo "  <div class=\"card\">"
        echo "    <h2>Protocolos SSL/TLS detectados</h2>"
        echo "    <table>"
        echo "      <tr><th>Protocolo</th><th>Estado</th><th>Evidencia</th></tr>"
        echo "      <tr><td>SSLv2</td><td>$(printf '%s' "$PROTO_SSLV2_STATUS" | html_escape)</td><td><code>$(printf '%s' "$PROTO_SSLV2_LINE" | html_escape)</code></td></tr>"
        echo "      <tr><td>SSLv3</td><td>$(printf '%s' "$PROTO_SSLV3_STATUS" | html_escape)</td><td><code>$(printf '%s' "$PROTO_SSLV3_LINE" | html_escape)</code></td></tr>"
        echo "      <tr><td>TLS 1.0</td><td>$(printf '%s' "$PROTO_TLS10_STATUS" | html_escape)</td><td><code>$(printf '%s' "$PROTO_TLS10_LINE" | html_escape)</code></td></tr>"
        echo "      <tr><td>TLS 1.1</td><td>$(printf '%s' "$PROTO_TLS11_STATUS" | html_escape)</td><td><code>$(printf '%s' "$PROTO_TLS11_LINE" | html_escape)</code></td></tr>"
        echo "      <tr><td>TLS 1.2</td><td>$(printf '%s' "$PROTO_TLS12_STATUS" | html_escape)</td><td><code>$(printf '%s' "$PROTO_TLS12_LINE" | html_escape)</code></td></tr>"
        echo "      <tr><td>TLS 1.3</td><td>$(printf '%s' "$PROTO_TLS13_STATUS" | html_escape)</td><td><code>$(printf '%s' "$PROTO_TLS13_LINE" | html_escape)</code></td></tr>"
        echo "    </table>"
        echo "  </div>"

        echo "  <div class=\"card\">"
        echo "    <h2>Hallazgos inseguros detectados</h2>"
        if [[ ${#FINDING_TITLE[@]} -eq 0 ]]; then
            echo "    <p>No se detectaron hallazgos inseguros con las reglas actuales.</p>"
        else
            echo "    <table>"
            echo "      <tr><th>#</th><th>Severidad</th><th>Hallazgo</th><th>Evidencia</th><th>Recomendación</th></tr>"

            for i in "${!FINDING_TITLE[@]}"; do
                sev_class=$(printf '%s' "${FINDING_SEVERITY[$i]}" | tr '[:upper:]' '[:lower:]')
                echo "      <tr>"
                echo "        <td>$((i+1))</td>"
                echo "        <td><span class=\"sev $sev_class\">$(printf '%s' "${FINDING_SEVERITY[$i]}" | html_escape)</span></td>"
                echo "        <td>$(printf '%s' "${FINDING_TITLE[$i]}" | html_escape)</td>"
                echo "        <td><code>$(printf '%s' "${FINDING_EVIDENCE[$i]}" | html_escape)</code></td>"
                echo "        <td>$(printf '%s' "${FINDING_RECOMMENDATION[$i]}" | html_escape)</td>"
                echo "      </tr>"
            done

            echo "    </table>"
        fi
        echo "  </div>"

        echo "</body>"
        echo "</html>"
    } > "$HTML_OUT"

    echo "[OK] Reporte HTML generado en: $HTML_OUT"
}

run_analysis_for_target() {
    TARGET="$1"
    SAFE_TARGET=$(sanitize_target_name "$TARGET")

    TESTSSL_OUT="$OUTDIR/testssl_${SAFE_TARGET}.txt"
    NMAP_OUT="$OUTDIR/nmap_${SAFE_TARGET}.txt"
    HTML_OUT="$OUTDIR/reporte_${SAFE_TARGET}.html"

    reset_findings

    echo
    echo "[*] Iniciando análisis sobre $TARGET ..."
    echo

    if ! is_resolvable "$TARGET"; then
        TARGET_STATUS="DNS_ERROR"
        TARGET_STATUS_DETAIL="El dominio no es resoluble."
        OVERALL_RISK="NO EVALUABLE"
        echo "[ERROR] $TARGET -> $TARGET_STATUS_DETAIL"
        print_executive_summary
        generate_html_report
        return
    fi

    echo "[*] Verificando accesibilidad del puerto 443..."
    if ! check_port_443 "$TARGET"; then
        OVERALL_RISK="NO EVALUABLE"
        echo "[ERROR] $TARGET -> $TARGET_STATUS_DETAIL"
        print_executive_summary
        generate_html_report
        return
    fi
    echo "[OK] Puerto 443 accesible."

    echo "[*] Ejecutando nmap..."
    if run_nmap_with_timeout; then
        echo "[OK] Resultado de nmap guardado en: $NMAP_OUT"
    else
        OVERALL_RISK="NO EVALUABLE"
        echo "[ERROR] $TARGET -> $TARGET_STATUS_DETAIL"
        print_executive_summary
        generate_html_report
        return
    fi

    echo "[*] Ejecutando testssl.sh..."
    if run_testssl_with_timeout; then
        echo "[OK] Resultado de testssl.sh guardado en: $TESTSSL_OUT"
    else
        OVERALL_RISK="NO EVALUABLE"
        echo "[ERROR] $TARGET -> $TARGET_STATUS_DETAIL"
        print_executive_summary
        generate_html_report
        return
    fi

    TARGET_STATUS="OK"
    TARGET_STATUS_DETAIL="Análisis completado correctamente."

    echo
    echo "=============================================="
    echo "Resumen de protocolos SSL/TLS detectados"
    echo "=============================================="

    print_separator
    check_protocol_version "SSLv2" "^ SSLv2"
    print_separator
    check_protocol_version "SSLv3" "^ SSLv3"
    print_separator
    check_protocol_version "TLS 1.0" "^ TLS 1[[:space:]]"
    print_separator
    check_protocol_version "TLS 1.1" "^ TLS 1\.1"
    print_separator
    check_protocol_version "TLS 1.2" "^ TLS 1\.2"
    print_separator
    check_protocol_version "TLS 1.3" "^ TLS 1\.3"
    print_separator

    parse_findings
    calculate_overall_risk
    print_executive_summary
    print_findings
    generate_html_report

    echo "=============================================="
    echo "Archivos generados:"
    echo " - $TESTSSL_OUT"
    echo " - $NMAP_OUT"
    echo " - $HTML_OUT"
    echo "=============================================="
}

main() {
    show_banner
    get_targets

    for target in "${TARGETS[@]}"; do
        run_analysis_for_target "$target"
    done
}

main

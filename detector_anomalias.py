import logging
from logging.handlers import RotatingFileHandler
from scapy.all import sniff, IP, ICMP, TCP, UDP, Raw
from collections import defaultdict, deque
import time
import statistics
import re  # Para detectar patrones en el contenido

# Configurar el sistema de logs rotatorio
LOG_FILE = 'anomaly_detection.log'
LOG_MAX_SIZE = 5 * 1024 * 1024  # Tamaño máximo del archivo de log (5 MB)
LOG_BACKUP_COUNT = 3  # Número de archivos de respaldo (backups)

# Crear un manejador de logs rotatorio
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_SIZE, backupCount=LOG_BACKUP_COUNT)
handler.setLevel(logging.INFO)

# Formato del log
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)

# Configurar el logger con el manejador
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)


# Definir variables para seguimiento
packet_count_per_ip = defaultdict(int)  # Conteo de paquetes por IP
packet_rate_per_ip = defaultdict(lambda: deque(maxlen=10))  # Historial de tasa de paquetes por IP (últimos 10 intervalos)
start_time = time.time()

# Ajustes de umbrales dinámicos
THRESHOLD_MULTIPLIER = 2  # Multiplicador del promedio para definir una anomalía en el tráfico
MONITORING_INTERVAL = 60  # Segundos
HIGH_TRAFFIC_PORTS = [22, 53, 80, 443]  # Puertos comunes (SSH, DNS, HTTP, HTTPS)
ICMP_THRESHOLD = 50  # Umbral de paquetes ICMP para identificar posibles ataques de ping flood
PAYLOAD_THRESHOLD = 100  # Tamaño del payload para detectar tráfico inusual

# Lista ampliada de patrones maliciosos
MALICIOUS_PATTERNS = [
    # Patrones de SQL Injection
    b"SELECT", b"UNION", b"INSERT", b"DELETE", b"UPDATE", b"' OR '1'='1'", b"DROP", b"ALTER", b"CREATE", b"TRUNCATE", b"exec", b"xp_cmdshell",
    b"UNION SELECT", b"--", b"' OR 1=1",  # Común en SQLi

    # Patrones de comandos shell maliciosos
    b"/bin/bash", b"/bin/sh", b"wget", b"curl", b"chmod", b"&&", b"|", b"sudo", b"scp", b"ftp", b"nc", b"nmap",

    # Inyecciones en PHP/Servidor Web
    b"<?php", b"eval(", b"system(", b"passthru(", b"shell_exec(", b"exec(", b"base64_decode(", b"$_GET", b"$_POST",

    # XSS - Cross-Site Scripting
    b"<script>", b"alert(", b"document.cookie", b"onerror=", b"onload=",

    # Patrones de exfiltración de datos o acceso a archivos críticos
    b"/etc/passwd", b"/etc/shadow", b"C:\\Windows\\System32\\", b".htpasswd", b"../../",

    # Patrones de ataques a aplicaciones web comunes
    b"admin'--", b"' OR 1=1 --", b"' OR 'x'='x", b"' OR 'a'='a", b"'='", b"' AND 'a'='a"
]

def calculate_packet_rate(ip_src):
    """Calcula la tasa de paquetes por IP, basada en los últimos intervalos."""
    current_time = time.time()
    elapsed_time = current_time - start_time

    # Actualizar la tasa de paquetes por segundo
    rate = packet_count_per_ip[ip_src] / elapsed_time
    packet_rate_per_ip[ip_src].append(rate)

    # Calcular el promedio de las últimas tasas
    avg_rate = statistics.mean(packet_rate_per_ip[ip_src])
    return rate, avg_rate

def detect_malicious_payload(payload):
    """Analiza el contenido del payload para detectar patrones sospechosos."""
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, payload):
            return True, pattern.decode('utf-8')
    return False, None

def detect_anomalies(packet):
    """ Analiza los paquetes para detectar anomalías avanzadas en la red. """
    global packet_count_per_ip

    # Solo analizamos paquetes IP
    if IP in packet:
        ip_src = packet[IP].src

        # Aumentar el conteo de paquetes de la IP origen
        packet_count_per_ip[ip_src] += 1

        # Calcular tasa de paquetes y el promedio móvil
        current_rate, avg_rate = calculate_packet_rate(ip_src)

        # Detectar picos de tráfico: Si la tasa actual es mucho mayor que el promedio
        if current_rate > avg_rate * THRESHOLD_MULTIPLIER:
            alert_subject = f"ALERTA: Pico de tráfico desde {ip_src}"
            alert_body = (f"IP {ip_src} tiene una tasa de tráfico de {current_rate:.2f} paquetes/seg, "
                          f"que es significativamente mayor que el promedio de {avg_rate:.2f} paquetes/seg.")
            print(f"[ALERTA] {alert_body}")
            log_alert(alert_subject, alert_body)

        # Detectar tráfico ICMP (ej. ataque de ping flood)
        if ICMP in packet:
            if packet_count_per_ip[ip_src] > ICMP_THRESHOLD:
                alert_subject = f"ALERTA: Posible ataque ICMP (ping flood) desde {ip_src}"
                alert_body = (f"IP {ip_src} ha enviado más de {ICMP_THRESHOLD} paquetes ICMP.")
                print(f"[ALERTA] {alert_body}")
                log_alert(alert_subject, alert_body)

        # Detectar tráfico TCP/UDP inusual en puertos sensibles o no comunes
        if TCP in packet or UDP in packet:
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
            if dport not in HIGH_TRAFFIC_PORTS:  # Detectar tráfico en puertos no comunes
                alert_subject = f"ALERTA: Tráfico en puerto no común {dport} desde {ip_src}"
                alert_body = f"Se detectó tráfico desde la IP {ip_src} hacia el puerto {dport}, que no es habitual."
                print(f"[ALERTA] {alert_body}")
                log_alert(alert_subject, alert_body)

            # Análisis de payload para detectar posibles comportamientos inusuales
            if Raw in packet:
                payload = packet[Raw].load
                payload_size = len(payload)
                
                # Detección de payloads sospechosos
                if payload_size > PAYLOAD_THRESHOLD:
                    alert_subject = f"ALERTA: Payload inusualmente grande desde {ip_src}"
                    alert_body = f"Se detectó un payload de {payload_size} bytes desde {ip_src} hacia el puerto {dport}."
                    print(f"[ALERTA] {alert_body}")
                    log_alert(alert_subject, alert_body)

                # Detectar patrones maliciosos en el payload
                is_malicious, pattern = detect_malicious_payload(payload)
                if is_malicious:
                    alert_subject = f"ALERTA: Payload malicioso detectado desde {ip_src}"
                    alert_body = f"Se detectó el patrón '{pattern}' en el tráfico de {ip_src} hacia el puerto {dport}."
                    print(f"[ALERTA] {alert_body}")
                    log_alert(alert_subject, alert_body)

# Función para registrar las alertas
def log_alert(subject, body):
    """Registra las alertas en el archivo de logs rotatorio y las muestra en la consola."""
    log_message = f"{subject} - {body}"
    logger.info(log_message)
    print(f"[Registro] {subject}: {body}")

def monitor_network():
    """ Función principal que monitorea la red y detecta anomalías. """
    global start_time
    print(f"Comenzando el monitoreo de la red local durante {MONITORING_INTERVAL} segundos...")

    # Iniciar captura de paquetes
    sniff(prn=detect_anomalies, timeout=MONITORING_INTERVAL)

    # Mostrar resumen de las IPs que han enviado paquetes
    print("\nResumen de tráfico:")
    for ip, count in packet_count_per_ip.items():
        print(f"IP: {ip}, Paquetes enviados: {count}")

    print("Monitoreo finalizado.")


def log_alert(subject, body):
    """Registra las alertas en el archivo de logs y las muestra en la consola."""
    logging.info(f"{subject} - {body}")
    print(f"[Registro] {subject}: {body}")

def monitor_network():
    """ Función principal que monitorea la red y detecta anomalías. """
    global start_time
    print(f"Comenzando el monitoreo de la red local durante {MONITORING_INTERVAL} segundos...")

    # Iniciar captura de paquetes
    sniff(prn=detect_anomalies, timeout=MONITORING_INTERVAL)

    # Mostrar resumen de las IPs que han enviado paquetes
    print("\nResumen de tráfico:")
    for ip, count in packet_count_per_ip.items():
        print(f"IP: {ip}, Paquetes enviados: {count}")

    print("Monitoreo finalizado.")

if __name__ == "__main__":
    monitor_network()




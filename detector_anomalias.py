import smtplib
from email.mime.text import MIMEText
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

# Definir variables para seguimiento
packet_count_per_ip = defaultdict(int)
start_time = time.time()
THRESHOLD_PACKETS = 100  # Número de paquetes para considerar una IP sospechosa
MONITORING_INTERVAL = 60  # Segundos

# Configurar detalles de correo
SMTP_SERVER = 'smtp.office365.com'
SMTP_PORT = 587
SENDER_EMAIL = 'robcamgar@outlook.es'  # Cambia esto con tu correo
SENDER_PASSWORD = 'Manolito1973'  # Cambia esto con la contraseña de la cuenta
RECIPIENT_EMAIL = 'robcamargar@gmail.com'  # Cambia esto con el correo de destino

def send_alert(email_subject, email_body):
    """ Envía un correo electrónico con el asunto y cuerpo proporcionados. """
    if not email_subject or not email_body:
        print("[ERROR] El asunto y el cuerpo del correo no pueden estar vacíos.")
        return

    msg = MIMEText(email_body)
    msg['Subject'] = email_subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECIPIENT_EMAIL

    try:
        # Conectar al servidor SMTP y enviar el correo
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        print(f"[ALERTA] Correo enviado a {RECIPIENT_EMAIL} con el asunto: {email_subject}")
    except smtplib.SMTPAuthenticationError:
        print("[ERROR] Autenticación fallida, verifica las credenciales del correo.")
    except smtplib.SMTPException as e:
        print(f"[ERROR] Error al enviar el correo: {str(e)}")
    except Exception as e:
        print(f"[ERROR] Ocurrió un error inesperado: {str(e)}")

def detect_anomalies(packet):
    """ Analiza los paquetes para detectar anomalías en la red. """
    global packet_count_per_ip

    # Solo analizamos paquetes IP
    if IP in packet:
        ip_src = packet[IP].src

        # Aumentar el conteo de paquetes de la IP origen
        packet_count_per_ip[ip_src] = packet_count_per_ip.get(ip_src, 0) + 1

        # Imprimir paquetes anómalos si el umbral se supera
        if packet_count_per_ip.get(ip_src, 0) > THRESHOLD_PACKETS:
            alert_subject = f"ALERTA: IP sospechosa {ip_src}"
            alert_body = f"IP {ip_src} ha enviado más de {THRESHOLD_PACKETS} paquetes en un corto período de tiempo."
            print(f"[ALERTA] {alert_body}")
            send_alert(alert_subject, alert_body)

        # Detectar tráfico TCP/UDP inusual (por ejemplo, puertos sensibles)
        if TCP in packet or UDP in packet:
            dport = packet.getlayer(TCP).dport if TCP in packet else packet.getlayer(UDP).dport
            if dport in [22, 53]:
                alert_subject = f"ALERTA: Tráfico sensible detectado desde {ip_src}"
                alert_body = f"Tráfico hacia el puerto {dport} detectado desde {ip_src}."
                print(f"[ALERTA] {alert_body}")
                send_alert(alert_subject, alert_body)

def monitor_network():
    """ Función principal que monitorea la red y detecta anomalías. """
    try:
        global start_time
        print(f"Comenzando el monitoreo de la red local durante {MONITORING_INTERVAL} segundos...")

        # Iniciar captura de paquetes
        sniff(prn=detect_anomalies, timeout=MONITORING_INTERVAL)

        # Mostrar resumen de las IPs que han enviado paquetes
        print("\nResumen de tráfico:")
        for ip, count in packet_count_per_ip.items():
            print(f"IP: {ip}, Paquetes enviados: {count}")

        print("Monitoreo finalizado.")
    except Exception as e:
        print(f"[ERROR] Se ha producido una excepción durante el monitoreo de la red: {str(e)}")

if __name__ == "__main__":
    monitor_network()


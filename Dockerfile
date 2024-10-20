# Utiliza una imagen base de Python 3
FROM python:3.9-slim

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar los archivos del proyecto en el contenedor
COPY . .

# Instalar las dependencias desde el archivo requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Exponer el puerto 8080 (si el script llega a necesitarlo)
EXPOSE 8080

# Comando por defecto para ejecutar el script
CMD ["python", "detector_anomalias.py"]
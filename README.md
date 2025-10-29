# Labutec - Playbook de Gestión de Vulnerabilidades

## Requisitos Previos

### Obtener Token de Mistral AI
Antes de comenzar, es necesario obtener una clave API de Mistral AI:
1. Registrarse en [Mistral AI](https://mistral.ai/)
2. Crear una nueva API key en el dashboard
3. Guardar la clave de forma segura (formato: `xxxxxxxxxxxxxxxxxxxxxxxx`)

## Paso 1: Instalación de Wazuh

### 1.1 Dar permisos de ejecución al script de instalación
```bash
chmod +x startup_wazuh.command    # Para macOS
chmod +x startup_wazuh.sh  # Para Linux
```

### 1.2 Ejecutar el script de instalación
```bash
./startup_wazuh.command    # Para macOS
./startup_wazuh.sh  # Para Linux
```

## Paso 2: Agregar Agentes

### 2.1 Acceder a la interfaz gráfica de Wazuh
- Abrir navegador web y acceder a la URL de Wazuh: https://<ip_wazuh>
- Iniciar sesión con las credenciales correspondientes:
    user: admin
    password: SecretPassword

### 2.2 Configurar nuevo agente
1. Navegar a la sección de "Agents management" -> Summary
2. Seleccionar "Deploy new agent"
3. Seleccionar sistema operativo (tipo de arquitectura)
4. Completar los datos del host:
   - **Server address**: IP o nombre del servidor wazuh
5. Opcional (nombre del host):
   - **Agent Name**: Nombre para el agente
4. Obtener el comando de instalación generado
5. Ejecutar el comando en el host objetivo
6. opcionalmente se pueden gestionar los hosts desde: ./var/ossec/bin/manage_agents

## Paso 3: Configuración del Entorno Python

### 3.1 Crear entorno virtual
```bash
python3 -m venv venv
```

### 3.2 Activar entorno virtual
```bash
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
```

### 3.3 Instalar dependencias
```bash
pip install -r requirements.txt
```

## Paso 4: Escaneo de Vulnerabilidades

### 4.1 Ejecutar el escáner
```bash
python3 wazuh_opensearch_vuln_scanner.py --host <IP_WAZUH> --user <USUARIO>
```

### 4.2 Ingresar contraseña
- El script solicitará la contraseña de forma interactiva
- La contraseña no se mostrará en pantalla por seguridad

### 4.3 Resultado
- Se generará un archivo JSON con las vulnerabilidades encontradas
- Formato: `vulnerabilities_<IP_HOST>.json`

## Paso 5: Priorización Inteligente de Vulnerabilidades

### 5.1 Ejecutar el sistema de priorización
```bash
python3 priorizacion_vulnerabilities.py --severity CRITICAL,HIGH --wazuh-log <ARCHIVO_JSON> --mistral-key <API_KEY>
```

### 5.2 Parámetros disponibles
- `--severity`: Severidades a analizar (CRITICAL, HIGH, MEDIUM, LOW)
- `--wazuh-log`: Archivo JSON generado en el paso anterior
- `--mistral-key`: Clave API de Mistral AI para análisis inteligente

### 5.3 Reportes generados
El sistema genera múltiples reportes en la carpeta `reports/`:

- **Executive Summary**: Resumen ejecutivo con las 3 vulnerabilidades más críticas y métricas de riesgo para directivos
- **Technical Report**: Análisis técnico detallado con pasos de mitigación, sistemas afectados y cronograma de implementación
- **Attack Vectors Analysis**: Análisis de cadenas de ataque, mapeo MITRE ATT&CK y modelado de amenazas
- **Human Review Report**: Lista de vulnerabilidades que requieren revisión manual por conflictos entre IA y reglas
- **Comparison Report**: Comparación entre análisis de IA (Mistral) vs sistema basado en reglas
- **Approved Vulnerabilities**: Vulnerabilidades con consenso automático listas para implementación
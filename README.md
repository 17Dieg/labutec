# Labutec - Playbook de Gestión de Vulnerabilidades

## Paso 1: Instalación de Wazuh

### 1.1 Dar permisos de ejecución al script de instalación
```bash
chmod +x 755 startup_wazuh.command    # Para macOS
chmod +x 755 startup_wazuh.sh  # Para Linux
```

### 1.2 Ejecutar el script de instalación
```bash
./startup_wazuh_mac    # Para macOS
./startup_wazuh_linux  # Para Linux
```

## Paso 2: Agregar Agentes

### 2.1 Acceder a la interfaz gráfica de Wazuh
- Abrir navegador web y acceder a la URL de Wazuh: https://<ip_wazuh>
- Iniciar sesión con las credenciales correspondientes:
    user: admin
    password: SecretPassword
#./var/ossec/bin/manage_agents
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
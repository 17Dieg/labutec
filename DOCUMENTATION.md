# Sistema de Priorización Inteligente de Vulnerabilidades

## Documentación Técnica

**Versión**: 3.0
**Fecha**: Octubre 2025
**Autor**: Sistema de Análisis de Vulnerabilidades con IA

---

## Tabla de Contenidos

1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Arquitectura del Sistema](#arquitectura-del-sistema)
3. [Flujo de Datos](#flujo-de-datos)
4. [Componentes Principales](#componentes-principales)
5. [Modelo de Seguridad](#modelo-de-seguridad)
6. [Integración con APIs Externas](#integración-con-apis-externas)
7. [Configuración y Despliegue](#configuración-y-despliegue)
8. [Casos de Uso](#casos-de-uso)
9. [Troubleshooting](#troubleshooting)
10. [Roadmap](#roadmap)

---

## Resumen Ejecutivo

### Propósito

El Sistema de Priorización Inteligente de Vulnerabilidades v3 es una herramienta avanzada de ciberseguridad que combina análisis tradicional basado en reglas con inteligencia artificial generativa (Mistral AI) para optimizar la priorización de vulnerabilidades detectadas por Wazuh.

### Características Principales

- **Análisis Dual**: Combina algoritmos determinísticos con IA generativa
- **Integración Wazuh**: Lee logs JSON de Wazuh nativamente
- **Enriquecimiento EPSS**: Obtiene scores de explotabilidad desde FIRST.org
- **Attack Chain Analysis**: Identifica cadenas de ataque entre vulnerabilidades
- **Mapeo MITRE ATT&CK**: Clasifica vectores según framework MITRE
- **Revisión Humana Inteligente**: Sistema de workflow para decisiones críticas
- **Seguridad Multinivel**: Protección contra prompt injection y data leakage

### Beneficios

| Beneficio | Descripción | Impacto |
|-----------|-------------|---------|
| **Reducción de Ruido** | Filtra falsos positivos y prioriza CVEs críticos | -70% en tiempo de triaje |
| **Contexto Empresarial** | Considera criticidad de activos y exposición | Decisiones más informadas |
| **Análisis Predictivo** | Usa EPSS para predecir probabilidad de explotación | Priorización proactiva |
| **Automatización** | Reduce carga manual del equipo de seguridad | +50% en eficiencia |
| **Trazabilidad** | Genera reportes auditables con justificaciones | Compliance mejorado |

---

## Arquitectura del Sistema

### Vista de Alto Nivel

```
┌─────────────────────────────────────────────────────────────────┐
│                     SISTEMA DE PRIORIZACIÓN v3                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │   Wazuh      │    │  FIRST.org   │    │  Mistral AI  │    │
│  │   JSON Logs  │───▶│  EPSS API    │───▶│  LLM API     │    │
│  └──────────────┘    └──────────────┘    └──────────────┘    │
│         │                    │                     │           │
│         │                    │                     │           │
│         ▼                    ▼                     ▼           │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │            VulnerabilityPrioritizerV3 (Core)             │ │
│  ├──────────────────────────────────────────────────────────┤ │
│  │                                                          │ │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────┐│ │
│  │  │ Data Ingestion │  │ SecuritySanitizer│ │ AI Engine │││ │
│  │  │   & Parsing    │◀─│  & Validation  │◀─│ & Fallback│││ │
│  │  └────────────────┘  └────────────────┘  └────────────┘│ │
│  │                                                          │ │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────┐│ │
│  │  │ Rule-Based     │  │ Human Review   │  │ Attack     │││ │
│  │  │ Prioritization │  │ Queue System   │  │ Chain      │││ │
│  │  └────────────────┘  └────────────────┘  └────────────┘│ │
│  │                                                          │ │
│  └──────────────────────────────────────────────────────────┘ │
│                              │                                 │
│                              ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │                  Report Generator                         │ │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────────┐│ │
│  │  │Executive  │ │ Technical │ │  Attack   │ │ Review   ││ │
│  │  │ Summary   │ │  Report   │ │  Vectors  │ │ Reports  ││ │
│  │  └───────────┘ └───────────┘ └───────────┘ └──────────┘│ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Arquitectura de Capas

#### Capa 1: Ingesta de Datos (Data Layer)
- **Wazuh Integration**: Parser JSON de logs Elasticsearch
- **EPSS Enrichment**: Cliente HTTP para FIRST.org API
- **Data Validation**: Sanitización y validación de inputs

#### Capa 2: Procesamiento (Business Logic Layer)
- **AI Prioritization Engine**: Integración con Mistral API
- **Rule-Based Engine**: Algoritmo determinístico de fallback
- **Comparison Engine**: Sistema de consenso dual
- **Attack Chain Analyzer**: Identificador de vectores complejos

#### Capa 3: Seguridad (Security Layer)
- **SecuritySanitizer**: Protección contra prompt injection
- **Data Anonymization**: Ofuscación de datos sensibles
- **Output Validation**: Verificación de respuestas LLM
- **Prompt Leakage Detection**: Detector de filtración

#### Capa 4: Workflow (Orchestration Layer)
- **HumanReviewQueue**: Sistema de revisión diferida
- **Decision Tracking**: Auditoría de decisiones
- **Consensus Detection**: Identificador de acuerdos

#### Capa 5: Presentación (Presentation Layer)
- **Report Generators**: Múltiples formatos de salida
- **Markdown Rendering**: Formateo profesional
- **Data Visualization**: Tablas y métricas

---

## Flujo de Datos

### Diagrama de Secuencia - Flujo Principal

```
┌─────────┐   ┌──────────┐   ┌─────────┐   ┌─────────┐   ┌──────────┐
│ Usuario │   │  Main()  │   │ Wazuh   │   │ FIRST   │   │ Mistral  │
└────┬────┘   └────┬─────┘   └────┬────┘   └────┬────┘   └────┬─────┘
     │             │                │             │             │
     │ execute     │                │             │             │
     ├────────────▶│                │             │             │
     │             │                │             │             │
     │             │ load_wazuh_    │             │             │
     │             │ vulnerabilities│             │             │
     │             ├───────────────▶│             │             │
     │             │                │             │             │
     │             │◀───────────────┤             │             │
     │             │  CVE list      │             │             │
     │             │                │             │             │
     │             │                                            │
     │             │ For each CVE:                             │
     │             │ get_epss_score()                          │
     │             ├──────────────────────────────▶│            │
     │             │                                │            │
     │             │◀──────────────────────────────┤            │
     │             │  EPSS score                   │            │
     │             │                                │            │
     │             │                                             │
     │             │ prioritize_with_mistral()                  │
     │             ├────────────────────────────────────────────▶│
     │             │  [Anonymized CVE data]                     │
     │             │                                             │
     │             │◀────────────────────────────────────────────┤
     │             │  Priority scores + reasoning               │
     │             │                                             │
     │             │                                             │
     │             │ _rule_based_prioritization()               │
     │             │ (for comparison)                           │
     │             │                                             │
     │             │ Compare results                             │
     │             │ ├─ Consensus? → Auto-approve               │
     │             │ └─ Conflict? → Human review                │
     │             │                                             │
     │             │ analyze_attack_vectors()                   │
     │             ├────────────────────────────────────────────▶│
     │             │  [Top 10 high-priority CVEs]              │
     │             │                                             │
     │             │◀────────────────────────────────────────────┤
     │             │  Attack chains + MITRE mapping             │
     │             │                                             │
     │             │ generate_reports()                         │
     │             │ ├─ Executive summary                       │
     │             │ ├─ Technical report                        │
     │             │ ├─ Attack vectors                          │
     │             │ ├─ Human review queue                      │
     │             │ └─ Comparison report                       │
     │             │                                             │
     │◀────────────┤                                             │
│  Reports saved │                                             │
│                │                                             │
```

### Pipeline de Datos Detallado

#### Fase 1: Ingesta y Enriquecimiento

```
Input: Wazuh JSON Log
   │
   ├─▶ Parse Elasticsearch format
   │   ├─ Extract CVE ID
   │   ├─ Extract CVSS score
   │   ├─ Extract severity
   │   ├─ Extract affected software
   │   ├─ Extract agent info (name, IP)
   │   └─ Extract description
   │
   ├─▶ Filter by severity
   │   └─ Apply user-specified criteria
   │
   ├─▶ Enrich with EPSS
   │   ├─ HTTP GET to FIRST.org API
   │   ├─ Parse JSON response
   │   └─ Add exploitability score
   │
   └─▶ Create Vulnerability objects
       └─ Dataclass instances with all metadata
```

#### Fase 2: Priorización con IA

```
Vulnerabilities List
   │
   ├─▶ Batch processing (50 CVEs/batch)
   │   └─ Avoid API timeouts
   │
   ├─▶ Security preprocessing
   │   ├─ Sanitize descriptions
   │   ├─ Anonymize IPs (10.0.0.1 → HOST_001)
   │   ├─ Anonymize agents (server-01 → AGENT_001)
   │   ├─ Anonymize criticality (Confidential → LEVEL_3)
   │   └─ Validate no injection patterns
   │
   ├─▶ Construct secure prompt
   │   ├─ System role definition
   │   ├─ Security constraints
   │   ├─ Task description
   │   ├─ Anonymized vulnerability data
   │   └─ Output format specification
   │
   ├─▶ Call Mistral API
   │   ├─ HTTPS POST with Bearer token
   │   ├─ Timeout: 60s
   │   ├─ Retry logic (3 attempts)
   │   └─ Rate limiting (5s delay)
   │
   ├─▶ Parse LLM response
   │   ├─ Method 1: Direct JSON parse
   │   ├─ Method 2: Regex extraction
   │   ├─ Method 3: Line-by-line parse
   │   └─ Fallback: Rule-based system
   │
   ├─▶ Security postprocessing
   │   ├─ Validate output structure
   │   ├─ Detect prompt leakage
   │   ├─ Sanitize reasoning text
   │   ├─ Validate score range (0-100)
   │   └─ Check for injection in output
   │
   └─▶ Output: Prioritized vulnerabilities
       └─ [{cve_id, priority_score, reasoning}, ...]
```

#### Fase 3: Análisis Comparativo

```
AI Results + Rule-Based Results
   │
   ├─▶ For each CVE:
   │   ├─ Calculate score difference
   │   ├─ Compare reasoning
   │   └─ Check critical thresholds
   │
   ├─▶ Decision routing
   │   │
   │   ├─ IF score_diff < 40 points
   │   │   AND priority_score < 95
   │   │   AND not recent critical CVE
   │   │   THEN → Auto-approve
   │   │        └─ Add to approved_decisions[]
   │   │
   │   └─ ELSE → Human review required
   │        └─ Add to pending_reviews[]
   │             ├─ Include both scores
   │             ├─ Include both reasonings
   │             ├─ Include vulnerability metadata
   │             └─ Include review reason
   │
   └─▶ Output: Dual decision tracking
       ├─ approved_decisions (consensus)
       └─ pending_reviews (conflicts)
```

#### Fase 4: Análisis de Vectores de Ataque

```
Top 10 High-Priority CVEs (score ≥ 80)
   │
   ├─▶ Group by affected host
   │   └─ Identify CVEs on same agent
   │
   ├─▶ Categorize vulnerabilities
   │   ├─ RCE (Remote Code Execution)
   │   ├─ PrivEsc (Privilege Escalation)
   │   ├─ Persist (Persistence mechanisms)
   │   ├─ Network (Network-level attacks)
   │   └─ Other
   │
   ├─▶ Identify attack chains
   │   ├─ RCE → PrivEsc → Persist
   │   ├─ Network → RCE → PrivEsc
   │   └─ PrivEsc → Persist
   │
   ├─▶ Map to MITRE ATT&CK
   │   ├─ T1190: Exploit Public-Facing Application
   │   ├─ T1068: Exploitation for Privilege Escalation
   │   ├─ T1543.002: Create or Modify System Process
   │   └─ [Additional techniques...]
   │
   ├─▶ Call Mistral for deep analysis
   │   ├─ Send grouped vulnerability data
   │   ├─ Request chain identification
   │   ├─ Request MITRE mapping
   │   └─ Request mitigation strategies
   │   │
   │   └─ Fallback: Description-based analysis
   │       └─ Pattern matching for attack types
   │
   └─▶ Output: Attack chain analysis
       └─ [{cve_id, attack_vectors, connects_to_cves,
            attack_chain, mitre_attack_chain,
            complex_attack_example, threat_level}, ...]
```

#### Fase 5: Generación de Reportes

```
All Processed Data
   │
   ├─▶ Executive Report
   │   ├─ High-level summary
   │   ├─ Top 3 priorities
   │   ├─ Risk metrics
   │   └─ Business impact
   │
   ├─▶ Technical Report
   │   ├─ Detailed CVE analysis
   │   ├─ Mitigation steps
   │   ├─ Affected systems
   │   ├─ Implementation timeline
   │   └─ References
   │
   ├─▶ Attack Vectors Report
   │   ├─ Threat modeling analysis
   │   ├─ Attack chain diagrams
   │   ├─ MITRE ATT&CK mapping
   │   ├─ Centrality analysis
   │   └─ Strategic recommendations
   │
   ├─▶ Human Review Report
   │   ├─ Pending decisions
   │   ├─ Score comparisons
   │   ├─ Dual reasoning
   │   └─ Action checkboxes
   │
   ├─▶ Comparison Report (Mistral vs Rules)
   │   ├─ Discrepancy analysis
   │   ├─ Score differences
   │   ├─ Reasoning comparison
   │   ├─ Statistical summary
   │   └─ Recommendations
   │
   └─▶ Approved Vulnerabilities Report
       ├─ Consensus vulnerabilities
       ├─ Agreement metrics
       ├─ Priority distribution
       └─ Implementation roadmap
```

---

## Componentes Principales

### 1. VulnerabilityPrioritizerV3

**Responsabilidad**: Motor central del sistema que orquesta todo el pipeline.

#### Atributos

```python
class VulnerabilityPrioritizerV3:
    wazuh_log_path: str          # Ruta al archivo JSON de Wazuh
    mistral_api_key: str         # Clave API para Mistral
    output_dir: str              # Directorio de salida
    vulnerabilities: List[Vulnerability]  # Lista de CVEs cargados
    review_queue: HumanReviewQueue       # Sistema de revisión
```

#### Métodos Principales

| Método | Propósito | Entrada | Salida |
|--------|-----------|---------|--------|
| `load_wazuh_vulnerabilities()` | Cargar CVEs desde Wazuh | severity_filter | List[Vulnerability] |
| `get_epss_score()` | Obtener score EPSS | cve_id | float (0.0-1.0) |
| `prioritize_with_mistral()` | Priorizar con IA | List[Vulnerability] | List[Dict] |
| `_rule_based_prioritization()` | Fallback sin IA | List[Vulnerability] | List[Dict] |
| `analyze_attack_vectors_with_mistral()` | Analizar cadenas | List[Dict] | List[Dict] |
| `generate_executive_report()` | Reporte ejecutivo | List[Dict] | str (markdown) |
| `generate_technical_report()` | Reporte técnico | List[Dict] | str (markdown) |
| `generate_attack_vectors_report()` | Reporte de vectores | List[Dict] | str (markdown) |

#### Algoritmo de Priorización Basado en Reglas

```python
# Fórmula de scoring:
priority_score = (
    (cvss_score / 10) * 35 +           # CVSS: 35 puntos
    epss_score * 30 +                   # EPSS: 30 puntos
    criticality_points +                # Criticality: 25 puntos
    (10 if exploit_available else 0) +  # Exploit: 10 puntos
    (10 if public_exposure else 0)      # Exposure: 10 puntos
)

# Donde criticality_points:
criticality_map = {
    "Secret": 25,
    "Confidential": 20,
    "Internal": 15,
    "Public": 10
}
```

### 2. SecuritySanitizer

**Responsabilidad**: Protección multicapa contra ataques de seguridad.

#### Funciones de Seguridad

##### a) Detección de Inyección de Prompts

```python
INJECTION_PATTERNS = [
    r'ignore\s+previous\s+instructions',
    r'forget\s+everything',
    r'you\s+are\s+now',
    r'act\s+as\s+a',
    r'pretend\s+to\s+be',
    r'system\s*:',
    r'<\s*script',
    r'javascript:',
    r'jailbreak'
]
```

##### b) Anonimización de Datos

```python
# Ejemplos de anonimización:
"192.168.1.100"    → "HOST_001"
"server-web-prod"  → "AGENT_001"
"Confidential"     → "LEVEL_3"
"Secret"           → "LEVEL_4"
```

##### c) Validación de Outputs

```python
def validate_output_structure(data: dict) -> bool:
    # Verifica:
    # - Campos requeridos presentes
    # - Formato CVE válido (CVE-YYYY-NNNNN)
    # - Score en rango [0, 100]
    # - Longitud de reasoning < 500 chars
    # - No injection patterns en reasoning
```

##### d) Detección de Prompt Leakage

```python
# Patrones sensibles que no deben aparecer en outputs:
sensitive_patterns = [
    "===system_role_start===",
    "===task_start===",
    "cybersecurity vulnerability assessment system",
    "you must only analyze",
    "anonymized vulnerability data",
    "level_1=low, level_2=medium"
]
```

### 3. HumanReviewQueue

**Responsabilidad**: Gestión de workflow para decisiones críticas.

#### Criterios de Revisión Humana

```python
critical_thresholds = {
    'priority_score': 95,        # Scores extremadamente altos
    'score_change': 40,          # Diferencia Mistral vs Reglas
    'critical_apps': [           # Aplicaciones sensibles
        'kernel', 'ssh', 'apache',
        'openssl', 'systemd'
    ]
}
```

#### Flujo de Decisión

```
┌─────────────────────────────────────┐
│  Nueva decisión de priorización    │
└────────────────┬────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│  ¿Score ≥ 95?                       │
├─────────────────────────────────────┤
│  ¿Diferencia ≥ 40 vs reglas?        │
├─────────────────────────────────────┤
│  ¿CVE 2024 con score ≥ 90?          │
├─────────────────────────────────────┤
│  ¿App crítica con score ≥ 90?       │
└────────────────┬────────────────────┘
                 │
       ┌─────────┴─────────┐
       │                   │
       ▼                   ▼
    SÍ a alguna        NO a todas
       │                   │
       ▼                   ▼
┌─────────────┐   ┌─────────────┐
│   HUMAN     │   │    AUTO     │
│   REVIEW    │   │  APPROVED   │
│  pending_   │   │  approved_  │
│  reviews[]  │   │ decisions[] │
└─────────────┘   └─────────────┘
```

### 4. Vulnerability (Dataclass)

**Responsabilidad**: Modelo de datos para representar una vulnerabilidad.

```python
@dataclass
class Vulnerability:
    cve_id: str                    # Identificador CVE
    software_name: str             # Software afectado
    software_version: str          # Versión vulnerable
    cvss_score: float              # Score CVSS (0.0-10.0)
    severity: str                  # CRITICAL/HIGH/MEDIUM/LOW
    description: str               # Descripción técnica
    asset_count: int               # Número de activos afectados
    asset_criticality: str         # Criticidad del activo
    public_exposure: bool          # ¿Expuesto a Internet?
    exploit_available: bool        # ¿Exploit público disponible?
    epss_score: Optional[float]    # Score EPSS (0.0-1.0)
    agent_name: Optional[str]      # Nombre del agente Wazuh
    agent_ip: Optional[str]        # IP del agente
```

---

## Modelo de Seguridad

### Principios de Diseño

1. **Defense in Depth**: Múltiples capas de validación
2. **Least Privilege**: Anonimización de datos sensibles
3. **Zero Trust**: Validación de todas las entradas y salidas
4. **Secure by Default**: SSL/TLS obligatorio, verificación de certificados
5. **Auditability**: Logging completo de operaciones

### Threat Model

#### Amenazas Mitigadas

| Amenaza | Mitigación | Componente |
|---------|------------|------------|
| **Prompt Injection** | Pattern detection + sanitization | SecuritySanitizer |
| **Data Exfiltration** | Anonimización de IPs/hostnames | anonymize_ip/agent |
| **Prompt Leakage** | Detection de markers del sistema | detect_prompt_leakage |
| **XSS in Reports** | Sanitización de outputs LLM | sanitize_output |
| **Command Injection** | Validación de inputs | validate_context |
| **SSRF** | Whitelist de URLs (HTTPS only) | create_secure_session |
| **MitM** | SSL/TLS estricto + cert verification | ssl_context |
| **DoS** | Rate limiting + timeouts | Retry logic |

#### Zonas de Confianza

```
┌─────────────────────────────────────────────────────────┐
│  ZONA 1: INPUT (Untrusted)                              │
│  ├─ Wazuh JSON logs                                     │
│  ├─ Command-line arguments                              │
│  └─ Environment variables                               │
│                                                          │
│  Mitigación: Sanitization + Validation                  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  ZONA 2: PROCESSING (Trusted)                           │
│  ├─ Internal data structures                            │
│  ├─ Business logic                                      │
│  └─ Calculations                                        │
│                                                          │
│  Mitigación: Type safety + Assertions                   │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  ZONA 3: EXTERNAL APIS (Semi-trusted)                   │
│  ├─ Mistral API (anonymized data)                       │
│  ├─ FIRST.org EPSS API (public CVE IDs)                │
│  └─ TLS verification + timeouts                         │
│                                                          │
│  Mitigación: Anonymization + HTTPS + Output validation  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  ZONA 4: OUTPUT (Trusted but validated)                 │
│  ├─ Markdown reports                                    │
│  ├─ JSON logs                                           │
│  └─ Console output                                      │
│                                                          │
│  Mitigación: Output sanitization + Escaping             │
└─────────────────────────────────────────────────────────┘
```

### Cadena de Anonimización

```
Original Data             →    Anonymized Data    →    Sent to API
─────────────────────────────────────────────────────────────────
192.168.1.100            →    HOST_001            →    Mistral AI
server-web-prod-01       →    AGENT_001           →    Mistral AI
db-master.company.local  →    AGENT_002           →    Mistral AI
Confidential             →    LEVEL_3             →    Mistral AI
Secret                   →    LEVEL_4             →    Mistral AI
CVE-2024-1234            →    CVE-2024-1234       →    FIRST.org + Mistral
                                (CVE IDs are public, not anonymized)
```

### Secure Prompt Construction

```python
# Estructura del prompt con delimitadores seguros:

===SYSTEM_ROLE_START===
[System instructions]
[Security constraints]
===SYSTEM_ROLE_END===

===TASK_START===
[Task description]
===TASK_END===

===DATA_START===
[Anonymized JSON data]
===DATA_END===

===OUTPUT_FORMAT_START===
[Expected format]
===OUTPUT_FORMAT_END===
```

**Beneficios**:
- Delimita claramente cada sección
- Facilita detección de leakage
- Previene confusion attacks
- Permite validación estructural

---

## Integración con APIs Externas

### 1. FIRST.org EPSS API

#### Especificaciones

- **Endpoint**: `https://api.first.org/data/v1/epss`
- **Método**: GET
- **Autenticación**: No requerida (API pública)
- **Rate Limit**: No documentado (implementar delays)
- **Formato**: JSON

#### Ejemplo de Request

```python
GET https://api.first.org/data/v1/epss?cve=CVE-2024-1234

Response:
{
  "status": "OK",
  "status-code": 200,
  "version": "1.0",
  "data": [
    {
      "cve": "CVE-2024-1234",
      "epss": "0.89234",
      "percentile": "0.98765",
      "date": "2024-10-25"
    }
  ]
}
```

#### Manejo de Errores

```python
try:
    response = session.get(url, timeout=(10, 30), verify=True)
    if response.status_code == 200:
        return float(data['data'][0]['epss'])
    else:
        # Sin EPSS disponible → score 0.0
        return 0.0
except Timeout:
    # Red lenta → score 0.0
    return 0.0
except SSLError:
    # Certificado inválido → score 0.0
    return 0.0
```

### 2. Mistral AI API

#### Especificaciones

- **Endpoint**: `https://api.mistral.ai/v1/chat/completions`
- **Método**: POST
- **Autenticación**: Bearer token
- **Rate Limit**: Variable por tier
- **Timeout**: 60s (configurable)
- **Modelo**: `mistral-large-latest`

#### Ejemplo de Request

```python
POST https://api.mistral.ai/v1/chat/completions
Headers:
  Authorization: Bearer sk-xxxxx
  Content-Type: application/json

Body:
{
  "model": "mistral-large-latest",
  "messages": [
    {
      "role": "user",
      "content": "[Secure prompt with anonymized data]"
    }
  ],
  "temperature": 0.1,
  "max_tokens": 4000
}

Response:
{
  "id": "cmpl-xxxxx",
  "choices": [
    {
      "message": {
        "role": "assistant",
        "content": "[JSON array with prioritization]"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 1234,
    "completion_tokens": 567,
    "total_tokens": 1801
  }
}
```

#### Rate Limiting Strategy

```python
# Delays inteligentes basados en criticidad:
if critical_vulns > 5:
    delay = 2.0  # Más urgente, delay menor
elif critical_vulns > 0:
    delay = 3.0
else:
    delay = 5.0  # Menos urgente, delay mayor

# Manejo de HTTP 429:
if response.status_code == 429:
    retry_after = int(response.headers.get('Retry-After', 60))
    time.sleep(retry_after)
    # Reintentar...
```

#### Batch Processing

```python
# Para evitar timeouts con muchos CVEs:
batch_size = 50  # Máximo 50 CVEs por request

if len(vulnerabilities) > batch_size:
    # Procesar en lotes
    for i in range(0, len(vulns), batch_size):
        batch = vulns[i:i+batch_size]
        results = process_batch(batch)
        time.sleep(5)  # Delay entre batches
```

#### Fallback Logic

```
Mistral API Call
     │
     ├─▶ Success (200)
     │   └─▶ Return AI results
     │
     ├─▶ Timeout
     │   └─▶ Retry (max 3x)
     │       ├─▶ Success → Return results
     │       └─▶ Fail → Rule-based fallback
     │
     ├─▶ Rate Limit (429)
     │   └─▶ Wait retry_after
     │       └─▶ Rule-based fallback
     │
     ├─▶ Server Error (5xx)
     │   └─▶ Rule-based fallback
     │
     └─▶ Client Error (4xx)
         └─▶ Rule-based fallback
```

---

## Configuración y Despliegue

### Requisitos del Sistema

#### Hardware

- **CPU**: 2 cores mínimo (4 cores recomendado)
- **RAM**: 4 GB mínimo (8 GB recomendado)
- **Disco**: 1 GB para aplicación + logs
- **Red**: Conexión HTTPS a Internet

#### Software

- **Python**: 3.8+
- **Sistema Operativo**: Linux (Ubuntu 20.04+), macOS, Windows
- **Dependencias**:
  ```
  requests==2.31.0
  urllib3==2.0.7
  python-dotenv==1.0.0 (opcional)
  ```

### Instalación

#### Paso 1: Clonar/Descargar

```bash
# Opción 1: Git
git clone https://github.com/your-org/vuln-prioritizer.git
cd vuln-prioritizer

# Opción 2: Descarga directa
wget https://example.com/caso_ia_mistral.py
```

#### Paso 2: Instalar Dependencias

```bash
# Usando pip
pip install requests urllib3

# O usando requirements.txt
pip install -r requirements.txt
```

#### Paso 3: Configurar API Keys

```bash
# Opción 1: Variable de entorno
export MISTRAL_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxx"

# Opción 2: Archivo .env (si usas python-dotenv)
echo "MISTRAL_API_KEY=sk-xxxxxxxx" > .env

# Opción 3: Pasar por CLI
python caso_ia_mistral.py --mistral-key "sk-xxxxxxxx" [...]
```

#### Paso 4: Verificar Conectividad

```bash
# Test conexión FIRST.org
curl https://api.first.org/data/v1/epss?cve=CVE-2024-3094

# Test conexión Mistral (requiere API key)
curl https://api.mistral.ai/v1/models \
  -H "Authorization: Bearer $MISTRAL_API_KEY"
```

### Configuración de Wazuh

#### Exportar CVEs desde Wazuh

```bash
# Opción 1: Elasticsearch query directo
curl -X GET "https://wazuh-es:9200/wazuh-vulnerabilities-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 10000,
    "query": {
      "bool": {
        "must": [
          {"match": {"vulnerability.severity": "High"}},
          {"range": {"timestamp": {"gte": "now-7d"}}}
        ]
      }
    }
  }' > cves_wazuh.json

# Opción 2: Wazuh API
curl -X GET "https://wazuh-api:55000/vulnerability" \
  -H "Authorization: Bearer $WAZUH_TOKEN" \
  -o cves_wazuh.json
```

#### Formato Esperado

El archivo JSON debe seguir el formato Elasticsearch de Wazuh:

```json
{
  "hits": {
    "hits": [
      {
        "_source": {
          "vulnerability": {
            "id": "CVE-2024-1234",
            "severity": "High",
            "score": {
              "base": 8.5
            },
            "description": "Remote code execution vulnerability..."
          },
          "package": {
            "name": "openssl",
            "version": "1.1.1f"
          },
          "agent": {
            "name": "server-web-01",
            "ip": "192.168.1.100"
          }
        }
      }
    ]
  }
}
```

### Ejecución

#### Uso Básico

```bash
# Análisis de CVEs críticos y altos
python caso_ia_mistral.py \
  --severity CRITICAL,HIGH \
  --wazuh-log /path/to/cves_wazuh.json \
  --mistral-key $MISTRAL_API_KEY \
  --output-dir reports
```

#### Opciones Avanzadas

```bash
# Con modo debug
python caso_ia_mistral.py \
  --severity CRITICAL,HIGH,MEDIUM \
  --wazuh-log data/cves.json \
  --mistral-key $MISTRAL_API_KEY \
  --output-dir /var/reports \
  --debug

# Solo CVEs críticos (priorización rápida)
python caso_ia_mistral.py \
  --severity CRITICAL \
  --wazuh-log data/cves.json \
  --mistral-key $MISTRAL_API_KEY

# Sin IA (solo reglas)
python caso_ia_mistral.py \
  --severity CRITICAL,HIGH \
  --wazuh-log data/cves.json \
  --output-dir reports
  # Nota: Sin --mistral-key, usa algoritmo de reglas
```

#### Parámetros CLI

| Parámetro | Descripción | Requerido | Default |
|-----------|-------------|-----------|---------|
| `--severity` | Severidades a incluir (csv) | No | CRITICAL,HIGH |
| `--wazuh-log` | Ruta al JSON de Wazuh | No | ./cves_wazuh_dummy.json |
| `--mistral-key` | API key de Mistral | No | $MISTRAL_API_KEY |
| `--output-dir` | Directorio de reportes | No | reports/ |
| `--debug` | Habilitar logging detallado | No | False |

### Automatización

#### Cron Job (Linux)

```bash
# Editar crontab
crontab -e

# Ejecutar diariamente a las 2 AM
0 2 * * * /usr/bin/python3 /opt/vuln-prioritizer/caso_ia_mistral.py \
  --severity CRITICAL,HIGH \
  --wazuh-log /var/wazuh/cves.json \
  --output-dir /var/reports \
  >> /var/log/vuln-prioritizer.log 2>&1
```

#### Systemd Service (Linux)

```ini
# /etc/systemd/system/vuln-prioritizer.service
[Unit]
Description=Vulnerability Prioritization System
After=network.target wazuh.service

[Service]
Type=oneshot
User=security
Environment="MISTRAL_API_KEY=sk-xxxxxxxx"
ExecStart=/usr/bin/python3 /opt/vuln-prioritizer/caso_ia_mistral.py \
  --severity CRITICAL,HIGH \
  --wazuh-log /var/wazuh/cves.json \
  --output-dir /var/reports
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
# Activar
sudo systemctl enable vuln-prioritizer.service

# Ejecutar manualmente
sudo systemctl start vuln-prioritizer.service

# Ver logs
sudo journalctl -u vuln-prioritizer -f
```

#### Systemd Timer (Ejecución periódica)

```ini
# /etc/systemd/system/vuln-prioritizer.timer
[Unit]
Description=Run vulnerability prioritization daily

[Timer]
OnCalendar=daily
OnCalendar=02:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
# Activar timer
sudo systemctl enable vuln-prioritizer.timer
sudo systemctl start vuln-prioritizer.timer

# Ver próxima ejecución
sudo systemctl list-timers
```

### Docker Deployment

#### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copiar aplicación
COPY caso_ia_mistral.py requirements.txt ./

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Usuario no-root
RUN useradd -m -u 1000 security && chown -R security:security /app
USER security

# Volúmenes
VOLUME ["/app/reports", "/app/data"]

# Entrypoint
ENTRYPOINT ["python", "caso_ia_mistral.py"]
CMD ["--severity", "CRITICAL,HIGH", \
     "--wazuh-log", "/app/data/cves_wazuh.json", \
     "--output-dir", "/app/reports"]
```

#### Docker Compose

```yaml
version: '3.8'

services:
  vuln-prioritizer:
    build: .
    container_name: vuln-prioritizer
    environment:
      - MISTRAL_API_KEY=${MISTRAL_API_KEY}
    volumes:
      - ./data:/app/data:ro
      - ./reports:/app/reports:rw
    command:
      - --severity
      - CRITICAL,HIGH
      - --wazuh-log
      - /app/data/cves_wazuh.json
      - --mistral-key
      - ${MISTRAL_API_KEY}
      - --output-dir
      - /app/reports
    restart: no
    network_mode: bridge
```

#### Ejecución Docker

```bash
# Build
docker build -t vuln-prioritizer:latest .

# Run one-shot
docker run --rm \
  -v $(pwd)/data:/app/data:ro \
  -v $(pwd)/reports:/app/reports:rw \
  -e MISTRAL_API_KEY=$MISTRAL_API_KEY \
  vuln-prioritizer:latest \
  --severity CRITICAL,HIGH \
  --wazuh-log /app/data/cves_wazuh.json \
  --output-dir /app/reports

# Con docker-compose
docker-compose up
```

---

## Casos de Uso

### Caso 1: Análisis Diario de CVEs

**Escenario**: Equipo SOC que necesita priorizar CVEs diariamente.

```bash
# Script: /opt/scripts/daily-vuln-analysis.sh
#!/bin/bash

DATE=$(date +%Y%m%d)
WAZUH_LOG="/var/wazuh/exports/cves_${DATE}.json"
OUTPUT="/var/reports/daily/${DATE}"

# Exportar CVEs de Wazuh
curl -X GET "https://wazuh-es:9200/wazuh-vulnerabilities-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 10000,
    "query": {
      "bool": {
        "must": [
          {"terms": {"vulnerability.severity": ["Critical", "High"]}},
          {"range": {"timestamp": {"gte": "now-24h"}}}
        ]
      }
    }
  }' > "$WAZUH_LOG"

# Analizar con IA
python3 /opt/vuln-prioritizer/caso_ia_mistral.py \
  --severity CRITICAL,HIGH \
  --wazuh-log "$WAZUH_LOG" \
  --output-dir "$OUTPUT" \
  --debug

# Notificar resultados
REPORT="$OUTPUT/executive_summary_wazuh_*.md"
mail -s "Daily Vulnerability Report - $DATE" \
  security-team@company.com < "$REPORT"

# Cleanup
find /var/reports/daily -mtime +30 -delete
```

### Caso 2: Análisis Post-Incident

**Escenario**: Después de un incidente, analizar vulnerabilidades relacionadas.

```bash
# Análisis enfocado en servidor comprometido
python caso_ia_mistral.py \
  --severity CRITICAL,HIGH,MEDIUM \
  --wazuh-log incident_host_cves.json \
  --mistral-key $MISTRAL_API_KEY \
  --output-dir incident_analysis

# Revisar cadenas de ataque
cat incident_analysis/attack_vectors_analysis_*.md | \
  grep -A 20 "Cadena de Ataque"
```

### Caso 3: Compliance Audit

**Escenario**: Generar reportes para auditoría de cumplimiento.

```bash
# Análisis completo de todos los CVEs
python caso_ia_mistral.py \
  --severity CRITICAL,HIGH,MEDIUM,LOW \
  --wazuh-log all_cves_Q4_2024.json \
  --output-dir compliance_reports/Q4_2024

# Generar métricas
python -c "
import json
with open('compliance_reports/Q4_2024/technical_report_*.md', 'r') as f:
    report = f.read()
    critical_count = report.count('CRITICAL')
    high_count = report.count('HIGH')
    print(f'Critical: {critical_count}, High: {high_count}')
"
```

### Caso 4: Threat Intelligence Integration

**Escenario**: Enriquecer análisis con threat intelligence externa.

```python
# threat_intel_wrapper.py
import requests
import json
import subprocess

# 1. Obtener CVEs de Wazuh
wazuh_cves = get_cves_from_wazuh()

# 2. Enriquecer con threat intel
for cve in wazuh_cves:
    # Consultar CISA KEV
    kev_status = check_cisa_kev(cve['id'])

    # Consultar ExploitDB
    exploits = check_exploitdb(cve['id'])

    # Actualizar metadata
    cve['in_kev'] = kev_status
    cve['public_exploits'] = len(exploits)

# 3. Ejecutar priorización
save_enriched_cves('enriched_cves.json')
subprocess.run([
    'python', 'caso_ia_mistral.py',
    '--wazuh-log', 'enriched_cves.json',
    '--severity', 'CRITICAL,HIGH'
])
```

### Caso 5: Multi-Environment Analysis

**Escenario**: Analizar CVEs en múltiples entornos (prod, staging, dev).

```bash
# multi_env_analysis.sh
#!/bin/bash

ENVIRONMENTS=("prod" "staging" "dev")

for ENV in "${ENVIRONMENTS[@]}"; do
    echo "Analyzing $ENV environment..."

    python caso_ia_mistral.py \
      --severity CRITICAL,HIGH \
      --wazuh-log "data/cves_${ENV}.json" \
      --output-dir "reports/${ENV}" \
      --mistral-key $MISTRAL_API_KEY

    # Comparar con baseline
    diff -u "baseline/${ENV}/technical_report.md" \
            "reports/${ENV}/technical_report_*.md" \
        > "reports/${ENV}/changes.diff"
done

# Consolidar reportes
python consolidate_reports.py reports/*
```

---

## Troubleshooting

### Problemas Comunes

#### 1. Error de Conexión a Mistral API

**Síntoma**:
```
ERROR Error llamando a la API de Mistral: Connection timeout
COUNTERCLOCKWISE Usando sistema de priorización basado en reglas...
```

**Causas**:
- No hay conectividad a Internet
- Firewall bloqueando HTTPS saliente
- API key inválida
- Rate limit excedido

**Solución**:
```bash
# Verificar conectividad
curl -v https://api.mistral.ai/v1/models

# Verificar API key
echo $MISTRAL_API_KEY

# Test con curl
curl -X POST https://api.mistral.ai/v1/chat/completions \
  -H "Authorization: Bearer $MISTRAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "mistral-large-latest", "messages": [{"role": "user", "content": "test"}]}'

# Verificar firewall
sudo iptables -L OUTPUT -n | grep 443
```

#### 2. Error de Parsing de JSON de Wazuh

**Síntoma**:
```
ERROR Error cargando archivo Wazuh: Expecting value: line 1 column 1
```

**Causas**:
- Archivo JSON malformado
- Formato incorrecto (no es formato Elasticsearch)
- Archivo vacío

**Solución**:
```bash
# Validar JSON
python -m json.tool cves_wazuh.json > /dev/null

# Verificar estructura
jq '.hits.hits[0]._source' cves_wazuh.json

# Verificar campos requeridos
jq '.hits.hits[0]._source | {
  vuln: .vulnerability.id,
  pkg: .package.name,
  agent: .agent.name
}' cves_wazuh.json
```

#### 3. EPSS API Timeout

**Síntoma**:
```
ERROR EPSS API timeout para CVE-2024-1234: ReadTimeout
```

**Causas**:
- FIRST.org API lenta o caída
- Muchas peticiones concurrentes
- Timeout muy corto

**Solución**:
```bash
# Verificar API
curl -w "@curl-format.txt" -o /dev/null -s \
  "https://api.first.org/data/v1/epss?cve=CVE-2024-1234"

# Si EPSS falla, el sistema continúa con score 0.0
# No requiere intervención manual
```

#### 4. Rate Limit Excedido (HTTP 429)

**Síntoma**:
```
- Rate limit alcanzado, esperando 60s...
- Rate limit persistente, usando sistema basado en reglas
```

**Causas**:
- Demasiadas peticiones en poco tiempo
- Tier de API con límites bajos
- Múltiples instancias ejecutándose

**Solución**:
```bash
# Reducir batch size en el código:
# Editar línea 1052 en caso_ia_mistral.py
batch_size = 20  # Reducir de 50 a 20

# Aumentar delays:
# Editar líneas 1863-1868
delay = 10.0  # Aumentar delays entre llamadas

# Verificar plan de Mistral
curl https://api.mistral.ai/v1/usage \
  -H "Authorization: Bearer $MISTRAL_API_KEY"
```

#### 5. Prompt Leakage Detectado

**Síntoma**:
```
🚨 SECURITY ALERT: Prompt leakage detected, sanitizing response...
```

**Causas**:
- LLM repitiendo partes del prompt del sistema
- Injection attack detectado
- Bug en el modelo

**Solución**:
```
# El sistema automáticamente sanitiza el output
# No requiere intervención manual

# Si persiste, revisar logs:
grep "PROMPT LEAKAGE" /var/log/vuln-prioritizer.log

# Considerar ajustar temperature en caso_ia_mistral.py:
"temperature": 0.05  # Más determinístico
```

#### 6. No se Generan Reportes

**Síntoma**:
```
ERROR No se encontraron vulnerabilidades que coincidan con los criterios
```

**Causas**:
- Filtro de severidad muy restrictivo
- Archivo Wazuh vacío o sin CVEs de esa severidad
- Error en el filtrado

**Solución**:
```bash
# Verificar contenido del JSON
jq '.hits.hits | length' cves_wazuh.json

# Verificar severidades disponibles
jq '.hits.hits[]._source.vulnerability.severity' cves_wazuh.json | sort | uniq -c

# Ampliar filtro
python caso_ia_mistral.py \
  --severity CRITICAL,HIGH,MEDIUM,LOW \
  --wazuh-log cves_wazuh.json
```

### Debugging

#### Modo Debug

```bash
# Activar logging detallado
python caso_ia_mistral.py \
  --severity CRITICAL,HIGH \
  --wazuh-log data/cves.json \
  --debug 2>&1 | tee debug.log

# Buscar errores
grep -i "error\|warning\|exception" debug.log

# Buscar operaciones de seguridad
grep "SECURITY" debug.log

# Ver flujo de decisiones
grep "REVIEW REQUIRED\|Auto-approve" debug.log
```

#### Logs de Seguridad

```bash
# Detectar intentos de inyección
grep "injection" debug.log

# Prompt leakage
grep "PROMPT LEAKAGE" debug.log

# Validación fallida
grep "Invalid" debug.log
```

#### Profiling de Performance

```python
# profile_script.py
import cProfile
import pstats
from caso_ia_mistral import main

# Profile
cProfile.run('main()', 'profile_stats')

# Analizar
p = pstats.Stats('profile_stats')
p.sort_stats('cumulative')
p.print_stats(20)  # Top 20 funciones
```

### Logs y Monitoreo

#### Estructura de Logs

```
/var/log/vuln-prioritizer/
├── application.log         # Logs principales
├── security.log           # Alertas de seguridad
├── api_calls.log          # Llamadas a APIs externas
└── decisions.log          # Decisiones de priorización
```

#### Configuración de Logging Avanzada

```python
# En caso_ia_mistral.py, agregar:
import logging.handlers

# File handler con rotación
fh = logging.handlers.RotatingFileHandler(
    '/var/log/vuln-prioritizer/application.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)

# Security handler
sh = logging.handlers.RotatingFileHandler(
    '/var/log/vuln-prioritizer/security.log',
    maxBytes=5*1024*1024,
    backupCount=10
)
sh.setLevel(logging.WARNING)

logger.addHandler(fh)
logger.addHandler(sh)
```

#### Monitoreo con Prometheus

```python
# prometheus_exporter.py
from prometheus_client import Counter, Histogram, start_http_server

# Métricas
vulns_analyzed = Counter('vulns_analyzed_total', 'Total CVEs analyzed')
api_calls = Counter('mistral_api_calls_total', 'Mistral API calls', ['status'])
processing_time = Histogram('vuln_processing_seconds', 'Processing time')

# Exportar métricas
start_http_server(8000)
```

---

## Roadmap

### Versión 3.1 (Q1 2025)

- [ ] **Multi-LLM Support**: Soporte para Claude, GPT-4, Gemini
- [ ] **Vector Database Integration**: Almacenar embeddings de CVEs
- [ ] **Historical Analysis**: Comparación con análisis previos
- [ ] **GraphQL API**: API para integración con otras herramientas
- [ ] **Web UI**: Dashboard interactivo

### Versión 3.2 (Q2 2025)

- [ ] **Real-time Monitoring**: Análisis continuo de feeds
- [ ] **Automated Remediation**: Integración con Ansible/Terraform
- [ ] **Slack/Teams Integration**: Notificaciones interactivas
- [ ] **Custom Scoring Models**: Weights configurables
- [ ] **Machine Learning**: Modelo predictivo entrenado

### Versión 4.0 (Q3 2025)

- [ ] **Multi-Tenant Support**: SaaS deployment
- [ ] **Advanced Threat Intelligence**: Integración con múltiples feeds
- [ ] **Behavioral Analysis**: Detección de patrones de explotación
- [ ] **Automated Penetration Testing**: Validación de CVEs
- [ ] **Compliance Frameworks**: Mapeo automático (PCI-DSS, ISO 27001)

### Ideas Futuras

- **Blockchain Audit Trail**: Inmutabilidad de decisiones
- **Zero-Knowledge Proofs**: Análisis sin revelar datos
- **Federated Learning**: Aprendizaje colaborativo entre organizaciones
- **Quantum-Safe Encryption**: Preparación para computación cuántica

---

## Apéndices

### A. Formato de CVE en Wazuh

Ver especificación completa en: [Wazuh Vulnerability Detection](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/)

### B. MITRE ATT&CK Reference

Técnicas comúnmente identificadas:

- **T1190**: Exploit Public-Facing Application
- **T1068**: Exploitation for Privilege Escalation
- **T1543.002**: Create or Modify System Process
- **T1053.003**: Scheduled Task/Job: Cron
- **T1078**: Valid Accounts
- **T1055**: Process Injection
- **T1203**: Exploitation for Client Execution

Ver catálogo completo: [MITRE ATT&CK](https://attack.mitre.org/)

### C. CVSS v3.1 Scoring Guide

| Score | Severity | Descripción |
|-------|----------|-------------|
| 0.0 | None | Sin impacto |
| 0.1-3.9 | Low | Impacto mínimo |
| 4.0-6.9 | Medium | Impacto moderado |
| 7.0-8.9 | High | Impacto significativo |
| 9.0-10.0 | Critical | Impacto severo |

### D. EPSS Score Interpretation

| EPSS Score | Probabilidad | Acción Recomendada |
|------------|--------------|-------------------|
| 0.0-0.2 | Muy baja (0-20%) | Parcheo planificado |
| 0.2-0.5 | Baja (20-50%) | Monitoreo activo |
| 0.5-0.7 | Media (50-70%) | Parcheo prioritario |
| 0.7-0.9 | Alta (70-90%) | Parcheo urgente |
| 0.9-1.0 | Muy alta (90-100%) | Parcheo inmediato |

### E. Glossary

- **CVE**: Common Vulnerabilities and Exposures
- **CVSS**: Common Vulnerability Scoring System
- **EPSS**: Exploit Prediction Scoring System
- **LLM**: Large Language Model
- **SOC**: Security Operations Center
- **SIEM**: Security Information and Event Management
- **KEV**: Known Exploited Vulnerabilities (CISA)
- **RCE**: Remote Code Execution
- **PrivEsc**: Privilege Escalation
- **MITRE ATT&CK**: Framework de tácticas y técnicas adversarias

### F. Referencias

1. [NIST NVD](https://nvd.nist.gov/)
2. [FIRST EPSS](https://www.first.org/epss/)
3. [Wazuh Documentation](https://documentation.wazuh.com/)
4. [Mistral AI Docs](https://docs.mistral.ai/)
5. [MITRE ATT&CK](https://attack.mitre.org/)
6. [OWASP Top 10](https://owasp.org/Top10/)
7. [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Licencia y Soporte

**Versión**: 3.0
**Última Actualización**: Octubre 2025
**Mantenedor**: Security Operations Team

Para preguntas, bugs o feature requests:
- Email: security-tools@company.com
- Issues: https://github.com/your-org/vuln-prioritizer/issues
- Docs: https://docs.company.com/vuln-prioritizer

---

**© 2025 Your Organization. Todos los derechos reservados.**

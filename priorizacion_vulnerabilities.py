#!/usr/bin/env python3
"""
Vulnerability Prioritization System v3 with Wazuh JSON Log Integration
Uses vulnerability data from Wazuh JSON logs
Includes Mistral LLM for intelligent vulnerability prioritization
Includes Nuclei templates for real vulnerability validation and testing
"""

import os
import json
import argparse
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import requests
from dataclasses import dataclass
import os
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    cve_id: str
    software_name: str
    software_version: str
    cvss_score: float
    severity: str
    description: str
    asset_count: int
    asset_criticality: str
    public_exposure: bool
    exploit_available: bool
    epss_score: Optional[float] = None
    nuclei_templates: Optional[List[str]] = None
    agent_name: Optional[str] = None
    agent_ip: Optional[str] = None

@dataclass
class NucleiTemplate:
    id: str
    name: str
    severity: str
    cve_ids: List[str]
    description: str
    file_path: str
    tags: List[str]




class VulnerabilityPrioritizerV3:
    def __init__(self, wazuh_log_path: str = "/home/cgarciac/dummy/datos/dummy/cves_wazuh_dummy.json", mistral_api_key: Optional[str] = None, nuclei_templates_path: Optional[str] = None):
        self.wazuh_log_path = wazuh_log_path
        self.mistral_api_key = mistral_api_key
        self.nuclei_templates_path = nuclei_templates_path
        self.vulnerabilities = []
        self.nuclei_templates = []
    
    def get_epss_score(self, cve_id: str) -> float:
        """Get EPSS score from FIRST.org API"""
        try:
            url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and len(data['data']) > 0:
                    epss_score = float(data['data'][0].get('epss', 0.0))
                    print(f"      NETWORK EPSS API: {cve_id} = {epss_score:.4f}")
                    return epss_score
                else:
                    print(f"      WARNING  EPSS API: Sin datos para {cve_id}")
                    return 0.0
            else:
                print(f"      ERROR EPSS API error {response.status_code} para {cve_id}")
                return 0.0
                
        except Exception as e:
            print(f"      ERROR EPSS API excepción para {cve_id}: {e}")
            return 0.0
    
    def load_wazuh_vulnerabilities(self, severity_filter: List[str]) -> List[Vulnerability]:
        """Load vulnerability data from Wazuh JSON log"""
        print(f"\nSEARCH PASO 1: Cargando vulnerabilidades desde log de Wazuh...")
        print(f"   - Archivo: {self.wazuh_log_path}")
        
        if not os.path.exists(self.wazuh_log_path):
            print(f"   ERROR Archivo no encontrado: {self.wazuh_log_path}")
            return []
        
        try:
            with open(self.wazuh_log_path, 'r', encoding='utf-8') as f:
                wazuh_data = json.load(f)
            
            print(f"   - Datos cargados exitosamente")
            
            # Extraer vulnerabilidades del formato Elasticsearch de Wazuh
            hits = wazuh_data.get('hits', {}).get('hits', [])
            print(f"   - CVEs encontrados en el log: {len(hits)}")
            
            vulnerabilities = []
            
            # Mapeo de severidades de Wazuh a formato estándar
            severity_mapping = {
                'Critical': 'CRITICAL',
                'High': 'HIGH', 
                'Medium': 'MEDIUM',
                'Low': 'LOW'
            }
            
            for hit in hits:
                source = hit.get('_source', {})
                vulnerability_data = source.get('vulnerability', {})
                agent_data = source.get('agent', {})
                package_data = source.get('package', {})
                
                # Obtener severidad
                wazuh_severity = vulnerability_data.get('severity', 'Medium')
                standard_severity = severity_mapping.get(wazuh_severity, 'MEDIUM')
                
                # Filtrar por severidad si se especifica
                if severity_filter and standard_severity not in severity_filter:
                    continue
                
                # Extraer CVSS score del objeto cvss
                # cvss_data = vulnerability_data['score']['base']
                # cvss_score = 1.0
                # if isinstance(cvss_data, dict):
                #     cvss_score = float(cvss_data.get('cvss3', {}).get('base_score', 0.0))
                cvss_score = float(vulnerability_data['score']['base'])
                
                epss_aux = self.get_epss_score(vulnerability_data.get('id', ''))
                # Crear objeto Vulnerability
                vuln = Vulnerability(
                    cve_id=vulnerability_data.get('id', 'Unknown'),
                    software_name=package_data.get('name', 'Unknown'),
                    software_version=package_data.get('version', 'Unknown'),
                    cvss_score=cvss_score,
                    severity=standard_severity,
                    description=vulnerability_data.get('description', 'No description available'),
                    asset_count=1,  # Cada CVE afecta a un agente
                    asset_criticality='Internal',  # Valor por defecto
                    public_exposure=False,  # Valor por defecto
                    exploit_available=False,  # Valor por defecto
                    epss_score=epss_aux,  # Valor por defecto
                    agent_name=agent_data.get('name', 'Unknown'),
                    agent_ip=agent_data.get('ip', 'Unknown')
                )
                
                vulnerabilities.append(vuln)
                print(f"   WARNING  {vuln.cve_id} - {vuln.software_name} ({vuln.severity}) - Agente: {vuln.agent_name}")
            
            print(f"   SUCCESS Procesadas {len(vulnerabilities)} vulnerabilidades desde Wazuh")
            self.vulnerabilities = vulnerabilities
            return vulnerabilities
            
        except Exception as e:
            print(f"   ERROR Error cargando archivo Wazuh: {e}")
            logger.error(f"Error loading Wazuh log: {e}")
            return []
    def load_nuclei_templates(self) -> List[NucleiTemplate]:
        """Load and parse Nuclei templates from local directory or GitHub"""
        print("\nDNA PASO EXTRA: Cargando templates de Nuclei...")
        logger.debug("SEARCH DEBUG: Iniciando carga de templates de Nuclei")
        logger.debug(f"SEARCH DEBUG: Ruta de templates configurada: {self.nuclei_templates_path}")
        
        if not self.nuclei_templates_path:
            print("   - No se especificó ruta de templates, usando templates integrados...")
            logger.debug("SEARCH DEBUG: Usando templates integrados (built-in)")
            return self._get_builtin_nuclei_templates()
        
        if self.nuclei_templates_path.startswith("http"):
            print(f"   - Descargando templates desde: {self.nuclei_templates_path}")
            logger.debug(f"SEARCH DEBUG: Intentando descargar templates desde URL: {self.nuclei_templates_path}")
            return self._download_nuclei_templates()
        else:
            print(f"   - Cargando templates desde directorio local: {self.nuclei_templates_path}")
            logger.debug(f"SEARCH DEBUG: Cargando templates desde directorio local: {self.nuclei_templates_path}")
            return self._load_local_nuclei_templates()
    
    def _get_builtin_nuclei_templates(self) -> List[NucleiTemplate]:
        """Get built-in Nuclei template mappings for known CVEs"""
        builtin_templates = [
            NucleiTemplate(
                id="confluence-cve-2023-22515",
                name="Confluence Data Center and Server - Broken Access Control",
                severity="critical",
                cve_ids=["CVE-2023-22515"],
                description="Detects Confluence instances vulnerable to CVE-2023-22515",
                file_path="cves/2023/CVE-2023-22515.yaml",
                tags=["cve", "confluence", "atlassian"]
            ),
            NucleiTemplate(
                id="activemq-cve-2023-46604",
                name="Apache ActiveMQ RCE",
                severity="critical",
                cve_ids=["CVE-2023-46604"],
                description="Detects Apache ActiveMQ RCE vulnerability",
                file_path="cves/2023/CVE-2023-46604.yaml",
                tags=["cve", "activemq", "rce"]
            ),
            NucleiTemplate(
                id="xz-utils-cve-2024-3094",
                name="XZ Utils Backdoor",
                severity="critical",
                cve_ids=["CVE-2024-3094"],
                description="Detects XZ Utils backdoor vulnerability",
                file_path="cves/2024/CVE-2024-3094.yaml",
                tags=["cve", "xz-utils", "backdoor"]
            )
        ]
        
        print(f"   SUCCESS Cargados {len(builtin_templates)} templates integrados")
        for template in builtin_templates:
            print(f"   TEST_TUBE {template.id} - {template.name} ({template.severity.upper()})")
        
        return builtin_templates
    
    def _download_nuclei_templates(self) -> List[NucleiTemplate]:
        """Download Nuclei templates from GitHub repository"""
        templates = []
        try:
            # GitHub API endpoint for nuclei-templates repository
            api_url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/cves"
            
            print("   - Consultando GitHub API para templates de Nuclei...")
            response = requests.get(api_url, timeout=30)
            
            if response.status_code == 200:
                folders = response.json()
                print(f"   - Encontradas {len(folders)} carpetas de CVEs")
                
                # Limit to recent years to avoid too many requests
                recent_years = ["2023", "2024", "2025"]
                
                for folder in folders:
                    if folder["name"] in recent_years and folder["type"] == "dir":
                        year_url = folder["url"]
                        print(f"   - Procesando templates del año {folder['name']}...")
                        
                        year_response = requests.get(year_url, timeout=30)
                        if year_response.status_code == 200:
                            year_files = year_response.json()
                            
                            for file_info in year_files[:10]:  # Limit to first 10 files per year
                                if file_info["name"].endswith(".yaml"):
                                    template = self._parse_nuclei_template_from_github(file_info)
                                    if template:
                                        templates.append(template)
                        
                        # Rate limiting
                        import time
                        time.sleep(1)
                
                print(f"   SUCCESS Descargados {len(templates)} templates desde GitHub")
                
            else:
                print(f"   ERROR Error al acceder a GitHub API: {response.status_code}")
                return self._get_builtin_nuclei_templates()
                
        except Exception as e:
            print(f"   ERROR Error descargando templates: {e}")
            print("   COUNTERCLOCKWISE Usando templates integrados como fallback...")
            return self._get_builtin_nuclei_templates()
        
        return templates
    
    def _parse_nuclei_template_from_github(self, file_info: Dict) -> Optional[NucleiTemplate]:
        """Parse a Nuclei template from GitHub file info"""
        try:
            # Extract CVE from filename
            filename = file_info["name"]
            if not filename.startswith("CVE-"):
                return None
            
            cve_id = filename.replace(".yaml", "").replace(".yml", "")
            
            template = NucleiTemplate(
                id=f"github-{cve_id.lower()}",
                name=f"Nuclei Template for {cve_id}",
                severity="medium",  # Default, would need to parse actual file for real severity
                cve_ids=[cve_id],
                description=f"Nuclei template for {cve_id}",
                file_path=file_info["path"],
                tags=["cve", "nuclei", "github"]
            )
            
            return template
            
        except Exception as e:
            logger.warning(f"Error parsing template {file_info.get('name', 'unknown')}: {e}")
            return None
    
    def _load_local_nuclei_templates(self) -> List[NucleiTemplate]:
        """Load Nuclei templates from local directory"""
        templates = []
        
        if not os.path.exists(self.nuclei_templates_path):
            print(f"   ERROR Directorio no encontrado: {self.nuclei_templates_path}")
            return self._get_builtin_nuclei_templates()
        
        try:
            # Walk through the templates directory
            for root, dirs, files in os.walk(self.nuclei_templates_path):
                for file in files:
                    if file.endswith(('.yaml', '.yml')):
                        file_path = os.path.join(root, file)
                        template = self._parse_local_nuclei_template(file_path)
                        if template:
                            templates.append(template)
            
            print(f"   SUCCESS Cargados {len(templates)} templates desde directorio local")
            
        except Exception as e:
            print(f"   ERROR Error cargando templates locales: {e}")
            return self._get_builtin_nuclei_templates()
        
        return templates
    
    def _parse_local_nuclei_template(self, file_path: str) -> Optional[NucleiTemplate]:
        """Parse a local Nuclei template file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                template_data = yaml.safe_load(f)
            
            # Extract template information
            template_id = template_data.get('id', os.path.basename(file_path))
            name = template_data.get('info', {}).get('name', template_id)
            severity = template_data.get('info', {}).get('severity', 'medium')
            description = template_data.get('info', {}).get('description', '')
            tags = template_data.get('info', {}).get('tags', [])
            
            # Extract CVE IDs from classification
            cve_ids = []
            classification = template_data.get('info', {}).get('classification', {})
            if 'cve-id' in classification:
                cve_list = classification['cve-id']
                if isinstance(cve_list, list):
                    cve_ids = cve_list
                else:
                    cve_ids = [cve_list]
            
            template = NucleiTemplate(
                id=template_id,
                name=name,
                severity=severity,
                cve_ids=cve_ids,
                description=description,
                file_path=file_path,
                tags=tags if isinstance(tags, list) else []
            )
            
            return template
            
        except Exception as e:
            logger.warning(f"Error parsing template {file_path}: {e}")
            return None
    
    def match_templates_to_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Match Nuclei templates to discovered vulnerabilities"""
        print(f"\nVinculando templates de Nuclei con vulnerabilidades...")
        
        # Create a mapping of CVE to templates
        cve_to_templates = {}
        for template in self.nuclei_templates:
            for cve_id in template.cve_ids:
                if cve_id not in cve_to_templates:
                    cve_to_templates[cve_id] = []
                cve_to_templates[cve_id].append(template)
        
        # Match templates to vulnerabilities
        for vuln in vulnerabilities:
            matching_templates = cve_to_templates.get(vuln.cve_id, [])
            vuln.nuclei_templates = [t.id for t in matching_templates]
            
            if matching_templates:
                print(f"   TARGET {vuln.cve_id}: {len(matching_templates)} template(s) encontrado(s)")
                for template in matching_templates:
                    print(f"      - {template.id}: {template.name}")
            else:
                print(f"   WARNING  {vuln.cve_id}: Sin templates disponibles")
        
        return vulnerabilities
    
    def generate_nuclei_scan_commands(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[str]]:
        """Generate Nuclei scan commands for vulnerability validation"""
        print(f"\nMICROSCOPE PASO ADICIONAL: Generando comandos de Nuclei para validación...")
        
        scan_commands = {}
        
        for vuln in vulnerabilities:
            if vuln.nuclei_templates:
                commands = []
                
                # Get sample targets based on asset locations
                sample_targets = self._get_sample_targets_for_vulnerability(vuln)
                
                for template_id in vuln.nuclei_templates:
                    template = next((t for t in self.nuclei_templates if t.id == template_id), None)
                    if template:
                        for target in sample_targets:
                            # Generate Nuclei command
                            if self.nuclei_templates_path and os.path.exists(self.nuclei_templates_path):
                                # Local templates
                                cmd = f"nuclei -t {template.file_path} -target {target} -severity {template.severity}"
                            else:
                                # Use template ID for remote templates
                                cmd = f"nuclei -t {template.id} -target {target} -severity {template.severity}"
                            
                            commands.append(cmd)
                
                scan_commands[vuln.cve_id] = commands
                
                print(f"   TEST_TUBE {vuln.cve_id}: {len(commands)} comando(s) de escaneo generado(s)")
                for cmd in commands[:2]:  # Show first 2 commands
                    print(f"      $ {cmd}")
                if len(commands) > 2:
                    print(f"      ... y {len(commands) - 2} comando(s) más")
        
        return scan_commands
    
    def _get_sample_targets_for_vulnerability(self, vuln: Vulnerability) -> List[str]:
        """Get sample target IPs/URLs for vulnerability scanning"""
        targets = []
        
        # Use the agent IP from Wazuh data
        if vuln.agent_ip and vuln.agent_ip != 'Unknown':
            targets.append(vuln.agent_ip)
        
        # Add some default targets if none found
        if not targets:
            targets = ["192.168.1.1", "10.0.0.1"]
        
        return targets
    
    def prioritize_with_mistral(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
        """Use Mistral LLM to intelligently prioritize vulnerabilities"""
        print(f"\nAI PASO 2: Priorizando vulnerabilidades con IA...")
        logger.debug("SEARCH DEBUG: Iniciando priorización con Mistral LLM")
        logger.debug(f"SEARCH DEBUG: Número de vulnerabilidades a priorizar: {len(vulnerabilities)}")
        
        if not self.mistral_api_key:
            print("   WARNING  No se proporcionó clave API de Mistral")
            print("   COUNTERCLOCKWISE Usando sistema de priorización basado en reglas...")
            logger.warning("No Mistral API key provided, using rule-based prioritization")
            logger.debug("SEARCH DEBUG: Cambiando a priorización basada en reglas")
            return self._rule_based_prioritization(vulnerabilities)
        else:
            print("   KEY Clave API de Mistral detectada")
            print("   BRAIN Preparando consulta para Mistral AI...")
            logger.debug("SEARCH DEBUG: Clave API de Mistral disponible, procediendo con IA")
            logger.debug(f"SEARCH DEBUG: Longitud de la clave API: {len(self.mistral_api_key)} caracteres")
        
        # Prepare data for LLM including Nuclei template availability
        vuln_data = []
        for vuln in vulnerabilities:
            vuln_data.append({
                "cve_id": vuln.cve_id,
                "software": vuln.software_name,
                "cvss_score": vuln.cvss_score,
                "severity": vuln.severity,
                "description": vuln.description,
                "affected_assets": vuln.asset_count,
                "asset_criticality": vuln.asset_criticality,
                "public_exposure": vuln.public_exposure,
                "exploit_available": vuln.exploit_available,
                "epss_score": vuln.epss_score or 0.0,
                "nuclei_templates_available": len(vuln.nuclei_templates or []),
                "nuclei_templates": vuln.nuclei_templates or [],
                "agent_name": vuln.agent_name,
                "agent_ip": vuln.agent_ip
            })
        
        prompt = f"""You are a cybersecurity expert. Analyze these vulnerabilities and provide a prioritization score (1-100) for each.

IMPORTANT: Respond ONLY with a valid JSON array. Do not include any explanatory text before or after the JSON.

Consider these factors:
1. CVSS score and severity
2. EPSS score (exploit prediction) 
3. Asset criticality
4. Public exposure
5. Exploit availability
6. Business impact potential
7. Nuclei templates availability

Vulnerabilities data:
{json.dumps(vuln_data, indent=2)}

Respond with this exact JSON format:
[
  {{
    "cve_id": "CVE-XXXX-XXXX",
    "priority_score": 85.5,
    "reasoning": "High CVSS score, exploit available, critical assets affected"
  }}
]"""
        
        try:
            headers = {
                "Authorization": f"Bearer {self.mistral_api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": "mistral-large-latest",
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 2500
            }
            
            print("   - Enviando consulta a Mistral AI...")
            response = requests.post(
                "https://api.mistral.ai/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                
                print(f"   DEBUG Respuesta de Mistral: {content[:200]}...")
                
                # Try multiple JSON extraction methods
                priorities = None
                
                # Method 1: Direct JSON parsing if content starts with [
                try:
                    if content.strip().startswith('['):
                        priorities = json.loads(content.strip())
                        print("   SUCCESS JSON extraído directamente")
                except:
                    pass
                
                # Method 2: Extract JSON array with regex
                if not priorities:
                    import re
                    json_match = re.search(r'\[[\s\S]*?\]', content, re.DOTALL)
                    if json_match:
                        try:
                            json_string = json_match.group()
                            priorities = json.loads(json_string)
                            print("   SUCCESS JSON extraído con regex")
                        except:
                            pass
                
                # Method 3: Extract JSON objects and build array
                if not priorities:
                    try:
                        import re
                        # Find all JSON objects in the response
                        json_objects = re.findall(r'\{[^{}]*"cve_id"[^{}]*\}', content)
                        if json_objects:
                            priorities = []
                            for obj_str in json_objects:
                                try:
                                    obj = json.loads(obj_str)
                                    priorities.append(obj)
                                except:
                                    continue
                            if priorities:
                                print(f"   SUCCESS {len(priorities)} objetos JSON extraídos individualmente")
                    except:
                        pass
                
                # Method 4: Parse line by line for JSON-like content
                if not priorities:
                    try:
                        lines = content.split('\n')
                        priorities = []
                        current_obj = {}
                        
                        for line in lines:
                            line = line.strip()
                            # Look for CVE patterns
                            cve_match = re.search(r'(CVE-\d{4}-\d+)', line, re.IGNORECASE)
                            if cve_match:
                                # Save previous object if exists
                                if current_obj and 'cve_id' in current_obj:
                                    priorities.append(current_obj)
                                
                                # Start new object
                                current_obj = {"cve_id": cve_match.group(1)}
                                
                                # Try to extract score and reasoning from same line
                                score_match = re.search(r'(?:priority_score|score):\s*(\d+(?:\.\d+)?)', line, re.IGNORECASE)
                                if score_match:
                                    current_obj["priority_score"] = float(score_match.group(1))
                                
                                reasoning_match = re.search(r'(?:reasoning|reason):\s*(.+)', line, re.IGNORECASE)
                                if reasoning_match:
                                    current_obj["reasoning"] = reasoning_match.group(1).strip()
                            
                            elif current_obj and 'cve_id' in current_obj:
                                # Look for score in separate line
                                if 'priority_score' not in current_obj:
                                    score_match = re.search(r'(?:priority_score|score):\s*(\d+(?:\.\d+)?)', line, re.IGNORECASE)
                                    if score_match:
                                        current_obj["priority_score"] = float(score_match.group(1))
                                
                                # Look for reasoning in separate line
                                if 'reasoning' not in current_obj:
                                    reasoning_match = re.search(r'(?:reasoning|reason):\s*(.+)', line, re.IGNORECASE)
                                    if reasoning_match:
                                        current_obj["reasoning"] = reasoning_match.group(1).strip()
                        
                        # Add last object
                        if current_obj and 'cve_id' in current_obj:
                            priorities.append(current_obj)
                        
                        if priorities:
                            print(f"   SUCCESS {len(priorities)} vulnerabilidades parseadas línea por línea")
                    except:
                        pass
                
                if priorities:
                    # Validate and clean the data
                    valid_priorities = []
                    for p in priorities:
                        if isinstance(p, dict) and 'cve_id' in p:
                            # Ensure required fields
                            if 'priority_score' not in p:
                                p['priority_score'] = 50.0  # Default score
                            if 'reasoning' not in p:
                                p['reasoning'] = "Priorización automática"
                            valid_priorities.append(p)
                    
                    if valid_priorities:
                        print(f"   SUCCESS Priorización completada usando Mistral AI ({len(valid_priorities)} vulnerabilidades)")
                        logger.info("Successfully prioritized vulnerabilities using Mistral")
                        return valid_priorities
                
                print("   ERROR No se pudo extraer JSON válido de la respuesta de Mistral")
                print("   COUNTERCLOCKWISE Usando sistema de priorización basado en reglas...")
                return self._rule_based_prioritization(vulnerabilities)
            else:
                print(f"   ERROR Error de API Mistral: {response.status_code}")
                return self._rule_based_prioritization(vulnerabilities)
                
        except Exception as e:
            print(f"   ERROR Error llamando a la API de Mistral: {e}")
            logger.error(f"Error calling Mistral API: {e}")
            return self._rule_based_prioritization(vulnerabilities)
    
    def _rule_based_prioritization(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
        """Fallback rule-based prioritization when LLM is not available"""
        print("   DATA Aplicando algoritmo de priorización basado en reglas...")
        print("   STEP Criterios de puntuación:")
        print("      - CVSS Score (30 puntos máx)")
        print("      - EPSS Score (25 puntos máx)")
        print("      - Criticidad de activos (20 puntos máx)")
        print("      - Disponibilidad de exploit (10 puntos)")
        print("      - Exposición pública (10 puntos)")
        print("      - Templates Nuclei disponibles (5 puntos)")
        
        priorities = []
        
        for vuln in vulnerabilities:
            print(f"\n   SEARCH Analizando {vuln.cve_id}:")
            score = 0
            reasoning = []
            
            # CVSS contribution (30 points max)
            cvss_points = (vuln.cvss_score / 10) * 30
            score += cvss_points
            reasoning.append(f"CVSS {vuln.cvss_score}/10")
            print(f"      CHART CVSS: {vuln.cvss_score}/10 = {cvss_points:.1f} puntos")
            
            # EPSS contribution (25 points max)
            epss_points = vuln.epss_score * 25
            score += epss_points
            reasoning.append(f"EPSS {vuln.epss_score:.3f}")
            print(f"      NETWORK EPSS: {vuln.epss_score:.3f} = {epss_points:.1f} puntos")
            
            # Criticality contribution (20 points max)
            criticality_scores = {"Secret": 20, "Confidential": 15, "Internal": 10}
            crit_score = criticality_scores.get(vuln.asset_criticality, 5)
            score += crit_score
            reasoning.append(f"{vuln.asset_criticality} assets")
            print(f"      LOCKED Criticidad: {vuln.asset_criticality} = {crit_score} puntos")
            
            # Exploit availability (10 points max)
            if vuln.exploit_available:
                score += 10
                reasoning.append("exploit available")
                print(f"      POWER Exploit disponible = +10 puntos")
            else:
                print(f"      POWER Sin exploit conocido = 0 puntos")
            
            # Public exposure (10 points max)
            if vuln.public_exposure:
                score += 10
                reasoning.append("publicly exposed")
                print(f"      NETWORK Exposición pública = +10 puntos")
            else:
                print(f"      NETWORK Sin exposición pública = 0 puntos")
            
            # Nuclei templates availability (5 points max)
            if vuln.nuclei_templates:
                nuclei_points = min(len(vuln.nuclei_templates), 5)
                score += nuclei_points
                reasoning.append(f"{len(vuln.nuclei_templates)} nuclei templates")
                print(f"      TEST_TUBE Templates Nuclei: {len(vuln.nuclei_templates)} = +{nuclei_points} puntos")
            else:
                print(f"      TEST_TUBE Sin templates Nuclei = 0 puntos")
            
            final_score = min(score, 100)
            print(f"      TARGET Puntuación final: {final_score:.1f}/100")
            
            priorities.append({
                "cve_id": vuln.cve_id,
                "priority_score": final_score,
                "reasoning": "; ".join(reasoning)
            })
        
        sorted_priorities = sorted(priorities, key=lambda x: x['priority_score'], reverse=True)
        print(f"\n   SUCCESS Priorización completada - {len(sorted_priorities)} vulnerabilidades ordenadas por riesgo")
        
        return sorted_priorities
    
    def generate_executive_report(self, prioritized_vulns: List[Dict[str, Any]], scan_commands: Dict[str, List[str]]) -> str:
        """Generate executive summary report with Nuclei integration"""
        total_vulns = len(prioritized_vulns)
        critical_count = sum(1 for v in self.vulnerabilities if v.severity == "CRITICAL")
        high_count = sum(1 for v in self.vulnerabilities if v.severity == "HIGH")
        
        # Count vulnerabilities with Nuclei templates
        with_templates = sum(1 for v in self.vulnerabilities if v.nuclei_templates)
        
        # Count unique agents affected
        unique_agents = len(set(v.agent_name for v in self.vulnerabilities if v.agent_name != 'Unknown'))
        
        report = f"""
# RESUMEN EJECUTIVO DE GESTIÓN DE VULNERABILIDADES v3 - WAZUH

## Resumen General
- **Fecha de Evaluación**: {datetime.now().strftime('%d-%m-%Y')}
- **Total de Vulnerabilidades Identificadas**: {total_vulns}
- **Severidad Crítica**: {critical_count}
- **Severidad Alta**: {high_count}
- **Total de Agentes Afectados**: {unique_agents}
- **Vulnerabilidades con Templates Nuclei**: {with_templates}/{total_vulns}

## Resumen de Riesgos
El análisis de logs de Wazuh identificó {total_vulns} vulnerabilidades que requieren atención inmediata.
{critical_count} vulnerabilidades críticas representan un riesgo inmediato para las operaciones comerciales.

**Integración Nuclei**: {with_templates} vulnerabilidades tienen templates de validación disponibles para 
pruebas y confirmación inmediatas.

## Top 3 Vulnerabilidades Prioritarias
"""
        
        for i, vuln in enumerate(prioritized_vulns[:3], 1):
            
            
            print('*'*20)
            print("vuln:", vuln)
            vuln_obj = next(v for v in self.vulnerabilities if v.cve_id == vuln['cve_id'])
            nuclei_status = "SUCCESS Templates disponibles" if vuln_obj.nuclei_templates else "ERROR Sin templates"
            
            report += f"""
### {i}. {vuln['cve_id']} (Puntuación de Prioridad: {vuln['priority_score']:.1f})
- **Software**: {vuln_obj.software_name}
- **Severidad**: {vuln_obj.severity}
- **Agente Afectado**: {vuln_obj.agent_name} ({vuln_obj.agent_ip})
- **Templates Nuclei**: {nuclei_status}
- **Justificación**: {vuln['reasoning']}
"""
            
            if vuln_obj.cve_id in scan_commands:
                report += f"- **Comandos de Validación**: {len(scan_commands[vuln_obj.cve_id])} comandos Nuclei listos\n"
        
        report += f"""
## Recomendaciones
1. **Acción Inmediata Requerida**: Abordar las 3 principales vulnerabilidades en 24-48 horas
2. **Validación Nuclei**: Ejecutar los templates Nuclei proporcionados para confirmar vulnerabilidades
3. **Asignación de Recursos**: Priorizar el parcheo basado en criticidad de activos y resultados de validación
4. **Monitoreo Continuo**: Implementar escaneo automatizado con templates Nuclei

## Beneficios de la Integración Nuclei
- **Validación Automatizada**: {with_templates} vulnerabilidades pueden ser validadas automáticamente
- **Reducción de Falsos Positivos**: Los templates proporcionan confirmación precisa de vulnerabilidades
- **Pruebas Optimizadas**: Comandos listos para usar para verificación inmediata de vulnerabilidades

## Impacto Comercial
- **Agentes de alto riesgo**: {sum(1 for v in self.vulnerabilities if v.asset_criticality in ['Secret', 'Confidential'])} agentes contienen datos sensibles
- **Exposición potencial**: {sum(1 for v in self.vulnerabilities if v.public_exposure)} vulnerabilidades expuestas públicamente
- **Capacidad de pruebas**: {len(scan_commands)} escenarios de prueba de vulnerabilidades disponibles

*Reporte generado por el Sistema de Priorización de Vulnerabilidades v3 con datos de Wazuh e Integración Nuclei*
"""
        return report
    
    def generate_technical_report(self, prioritized_vulns: List[Dict[str, Any]], scan_commands: Dict[str, List[str]]) -> str:
        """Generate detailed technical report with mitigation guides and Nuclei commands"""
        
        # Mitigation guides database
        mitigation_guides = {
            "CVE-2023-46604": {
                "patch": "Actualizar Apache ActiveMQ a la versión 5.18.3 o posterior",
                "workaround": "Deshabilitar o restringir el acceso a la interfaz de administración de ActiveMQ",
                "references": [
                    "https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt",
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-46604"
                ]
            },
            "CVE-2024-3094": {
                "patch": "Actualizar xz-utils a versión segura inmediatamente",
                "workaround": "Deshabilitar SSH temporalmente si es posible",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                    "https://www.openwall.com/lists/oss-security/2024/03/29/4"
                ]
            }
        }
        
        # Count unique agents
        unique_agents = len(set(v.agent_name for v in self.vulnerabilities if v.agent_name != 'Unknown'))
        
        report = f"""
# REPORTE DETALLADO DE EVALUACIÓN DE VULNERABILIDADES v3 - WAZUH

## Detalles de la Evaluación
- **Fecha**: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}
- **Alcance**: {unique_agents} agentes Wazuh monitoreados
- **Metodología**: Evaluación de riesgos con IA utilizando CVSS, EPSS, contexto comercial e integración Nuclei
- **Templates Nuclei**: {len(self.nuclei_templates)} templates cargados para validación

## Resumen de Templates Nuclei
- **Fuentes de Templates**: {'Directorio local' if self.nuclei_templates_path and not self.nuclei_templates_path.startswith('http') else 'GitHub/Integrados'}
- **Templates Disponibles**: {len(self.nuclei_templates)}
- **Vulnerabilidades Coincidentes**: {sum(1 for v in self.vulnerabilities if v.nuclei_templates)}

## Detalles de Vulnerabilidades

"""
        
        for i, vuln_priority in enumerate(prioritized_vulns, 1):
            vuln = next(v for v in self.vulnerabilities if v.cve_id == vuln_priority['cve_id'])
            
            report += f"""
### {i}. {vuln.cve_id} - {vuln.software_name}

**Evaluación de Riesgo**
- Puntuación de Prioridad: {vuln_priority['priority_score']:.1f}/100
- Puntuación CVSS: {vuln.cvss_score}/10 ({vuln.severity})
- Puntuación EPSS: {vuln.epss_score:.3f}
- Agente Afectado: {vuln.agent_name} ({vuln.agent_ip})
- Criticidad del Activo: {vuln.asset_criticality}
- Templates Nuclei: {len(vuln.nuclei_templates or [])} disponibles

**Descripción**
{vuln.description}

**Sistemas Afectados**
- Software: {vuln.software_name} ({vuln.software_version})
- Agente: {vuln.agent_name} ({vuln.agent_ip})
- Clasificación de Activo: {vuln.asset_criticality}
- Exposición Pública: {'Sí' if vuln.public_exposure else 'No'}
- Exploits Conocidos: {'Sí' if vuln.exploit_available else 'No'}

**Validación Nuclei**
"""
            
            if vuln.nuclei_templates:
                report += f"SUCCESS {len(vuln.nuclei_templates)} template(s) disponibles para validación:\n"
                for template_id in vuln.nuclei_templates:
                    template = next((t for t in self.nuclei_templates if t.id == template_id), None)
                    if template:
                        report += f"- {template.name} ({template.id})\n"
                
                if vuln.cve_id in scan_commands:
                    report += f"\n**Comandos de Validación:**\n"
                    for cmd in scan_commands[vuln.cve_id][:3]:  # Show first 3 commands
                        report += f"```bash\n{cmd}\n```\n"
                    if len(scan_commands[vuln.cve_id]) > 3:
                        report += f"... y {len(scan_commands[vuln.cve_id]) - 3} comandos adicionales\n"
            else:
                report += "ERROR No hay templates Nuclei disponibles para esta vulnerabilidad\n"
            
            report += "\n**Pasos de Mitigación**\n"
            
            if vuln.cve_id in mitigation_guides:
                guide = mitigation_guides[vuln.cve_id]
                report += f"""
1. **Parche Inmediato**: {guide['patch']}
2. **Solución Temporal**: {guide['workaround']}
3. **Validación**: Usar los templates Nuclei anteriores para confirmar la presencia de la vulnerabilidad

**Referencias**
"""
                for ref in guide['references']:
                    report += f"- {ref}\n"
            else:
                report += """
1. **Gestión de Parches**: Aplicar inmediatamente las actualizaciones de seguridad del proveedor
2. **Control de Acceso**: Implementar segmentación de red y restricciones de acceso
3. **Monitoreo**: Desplegar reglas de detección para intentos de explotación
4. **Validación**: Usar los templates Nuclei disponibles para confirmar la vulnerabilidad
5. **Respaldo**: Asegurar que haya respaldos recientes disponibles antes del parcheo

**Referencias**
- Consultar avisos de seguridad del proveedor
- Monitorear el catálogo KEV de CISA para explotación activa
- Usar templates de la comunidad Nuclei para validación
"""
            
            report += "\n---\n"
        
        report += f"""

## Cronograma de Implementación

### Semana 1 (Crítico - Puntuación de Prioridad 80+)
- Abordar vulnerabilidades con riesgo inmediato de explotación
- Enfocarse en activos clasificados como Secreto y Confidencial
- Ejecutar escaneos de validación Nuclei para confirmación
- Implementar parches de emergencia

### Semana 2-3 (Alta Prioridad - Puntuación 60-79)
- Parcheo sistemático de vulnerabilidades de alto impacto
- Escaneo continuo con Nuclei para validación
- Implementar controles de monitoreo adicionales

### Mes 1 (Prioridad Media - Puntuación 40-59)
- Completar la remediación de vulnerabilidades restantes
- Realizar pruebas de validación con Nuclei
- Actualizar la línea base de seguridad

## Flujo de Trabajo de Integración Nuclei

### 1. Validación de Vulnerabilidades
```bash
# Ejemplo de flujo de trabajo de validación
for cve_id in {list(scan_commands.keys())[:3]}:
    nuclei -t templates/cves/{{cve_id}}.yaml -target {{target}} -o resultados-validacion.json
```

### 2. Monitoreo Continuo  
```bash
# Configurar escaneo automatizado
nuclei -t cves/ -list targets.txt -o escaneo-diario.json
```

### 3. Desarrollo de Templates Personalizados
- Desarrollar templates específicos para la organización
- Integrar con pipelines de CI/CD
- Automatizar la validación de vulnerabilidades

*Reporte técnico generado por el Sistema de Evaluación de Vulnerabilidades v3 con datos de Wazuh*
*La integración Nuclei proporciona capacidades automatizadas de validación y pruebas*
*Para preguntas o aclaraciones, consulte con el equipo de ciberseguridad*
"""
        
        return report

def main():
    print("START SISTEMA DE PRIORIZACIÓN INTELIGENTE DE VULNERABILIDADES v3")
    print("CON INTEGRACIÓN DE LOGS WAZUH JSON")
    print("DNA Y NUCLEI PARA VALIDACIÓN AUTOMÁTICA")
    print("=" * 75)
    
    parser = argparse.ArgumentParser(
        description="AI-Powered Vulnerability Prioritization System v3 with Wazuh JSON Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s --severity CRITICAL,HIGH --wazuh-log datos/dummy/cves_wazuh_dummy.json
  %(prog)s --severity CRITICAL --mistral-key YOUR_KEY --nuclei-templates github
  %(prog)s --severity HIGH,MEDIUM --nuclei-templates /path/to/templates --debug
        """
    )
    parser.add_argument("--severity", default="CRITICAL,HIGH",
                       help="Severidades a incluir (separadas por comas): CRITICAL,HIGH,MEDIUM,LOW")
    parser.add_argument("--wazuh-log", default="/home/cgarciac/dummy/datos/dummy/cves_wazuh_dummy.json",
                       help="Ruta al archivo JSON de logs de Wazuh con vulnerabilidades")
    parser.add_argument("--mistral-key", help="Clave API de Mistral para priorización IA")
    parser.add_argument("--output-dir", default="reports", help="Directorio de salida para reportes")
    parser.add_argument("--nuclei-templates", 
                       help="Ruta a templates de Nuclei (local directory, 'github', o URL)")
    parser.add_argument("--debug", action="store_true", 
                       help="Habilitar modo debug con logging detallado de todas las acciones")
    
    args = parser.parse_args()
    
    # Get Mistral API key from argument or environment variable
    mistral_key = args.mistral_key or os.getenv('MISTRAL_API_KEY')
    
    # Configure logging based on debug flag
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Modo debug habilitado - se mostrarán todos los detalles del proceso")
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    # Parse severities - handle both comma-separated and space-separated
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severities_input = args.severity.replace(" ", ",")  # Convert spaces to commas
    args.severity = [s.strip().upper() for s in severities_input.split(',') if s.strip()]
    
    logger.debug(f"SEARCH DEBUG: Parseando severidades de entrada: '{args.severity}'")
    logger.debug(f"SEARCH DEBUG: Severidades válidas disponibles: {valid_severities}")
    
    # Validate the parsed severities
    for severity in args.severity:
        if severity not in valid_severities:
            print(f"ERROR Error: '{severity}' no es una severidad válida.")
            print(f"   Severidades válidas: {', '.join(valid_severities)}")
            return
    
    print(f"CONFIG  CONFIGURACIÓN DEL ANÁLISIS:")
    print(f"   - Severidades: {', '.join(args.severity)}")
    print(f"   - Log Wazuh: {args.wazuh_log}")
    print(f"   - Mistral API: {'SUCCESS Configurada' if mistral_key else 'ERROR No configurada'}")
    print(f"   - Directorio reportes: {args.output_dir}")
    print(f"   - Templates Nuclei: {args.nuclei_templates or 'TOOL Templates integrados'}")
    print(f"   - Modo Debug: {'SUCCESS Habilitado' if args.debug else 'ERROR Deshabilitado'}")
    
    logger.debug(f"SEARCH DEBUG: Configuración completa - severidades: {args.severity}, wazuh_log: {args.wazuh_log}, mistral_key: {'presente' if mistral_key else 'ausente'}, output_dir: {args.output_dir}, nuclei_templates: {args.nuclei_templates}, debug: {args.debug}")
    
    # Initialize prioritizer
    prioritizer = VulnerabilityPrioritizerV3(
        wazuh_log_path=args.wazuh_log,
        mistral_api_key=mistral_key,
        nuclei_templates_path=args.nuclei_templates
    )
    
    # Load Nuclei templates
    prioritizer.nuclei_templates = prioritizer.load_nuclei_templates()
    
    # Load vulnerabilities from Wazuh log
    logger.debug("SEARCH DEBUG: Cargando vulnerabilidades desde log de Wazuh")
    vulnerabilities = prioritizer.load_wazuh_vulnerabilities(args.severity)
    logger.debug(f"SEARCH DEBUG: Vulnerabilidades cargadas: {len(vulnerabilities)}")
    
    if not vulnerabilities:
        print("\nERROR No se encontraron vulnerabilidades que coincidan con los criterios especificados")
        logger.warning("No vulnerabilities found matching the specified criteria")
        logger.debug("SEARCH DEBUG: Terminando ejecución - no hay vulnerabilidades para procesar")
        return
    
    # Match Nuclei templates to vulnerabilities
    vulnerabilities = prioritizer.match_templates_to_vulnerabilities(vulnerabilities)
    
    # Prioritize using AI
    prioritized = prioritizer.prioritize_with_mistral(vulnerabilities)
    
    # Generate Nuclei scan commands
    scan_commands = prioritizer.generate_nuclei_scan_commands(vulnerabilities)
    
    print(f"\nREPORT PASO 3: Generando reportes...")
    print("   - Creando reporte ejecutivo con integración Nuclei...")
    exec_report = prioritizer.generate_executive_report(prioritized, scan_commands)
    print("   - Creando reporte técnico detallado con comandos de validación...")
    tech_report = prioritizer.generate_technical_report(prioritized, scan_commands)
    
    # Save reports
    print(f"   - Preparando directorio: {args.output_dir}")
    os.makedirs(args.output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    exec_file = f"{args.output_dir}/executive_summary_wazuh_{timestamp}.md"
    tech_file = f"{args.output_dir}/technical_report_wazuh_{timestamp}.md"
    scan_file = f"{args.output_dir}/nuclei_commands_{timestamp}.json"
    
    print(f"   - Guardando reporte ejecutivo: {exec_file}")
    with open(exec_file, "w", encoding="utf-8") as f:
        f.write(exec_report)
    
    print(f"   - Guardando reporte técnico: {tech_file}")
    with open(tech_file, "w", encoding="utf-8") as f:
        f.write(tech_report)
    
    print(f"   - Guardando comandos Nuclei: {scan_file}")
    with open(scan_file, "w", encoding="utf-8") as f:
        json.dump(scan_commands, f, indent=2)
    
    # Print summary
    print(f"\n{'='*80}")
    print("TARGET ANÁLISIS DE VULNERABILIDADES WAZUH v3 COMPLETADO")
    print(f"{'='*80}")
    print(f"DATA Total vulnerabilidades analizadas: {len(vulnerabilities)}")
    print(f"DNA Templates Nuclei cargados: {len(prioritizer.nuclei_templates)}")
    print(f"Vulnerabilidades con templates: {sum(1 for v in vulnerabilities if v.nuclei_templates)}")
    print(f"FOLDER Reportes generados en: {args.output_dir}/")
    print(f"\nTOP 3 VULNERABILIDADES PRIORITARIAS:")
    
    severity_spanish = {
        "CRITICAL": "CRÍTICA",
        "HIGH": "ALTA", 
        "MEDIUM": "MEDIA",
        "LOW": "BAJA"
    }
    
    for i, vuln in enumerate(prioritized[:3], 1):
        vuln_obj = next(v for v in vulnerabilities if v.cve_id == vuln['cve_id'])
        nuclei_status = f"TEST_TUBE {len(vuln_obj.nuclei_templates or [])} template(s)" if vuln_obj.nuclei_templates else "ERROR Sin templates"
        
        print(f"   {i}. {vuln['cve_id']} - Prioridad: {vuln['priority_score']:.1f}/100")
        print(f"      Software: {vuln_obj.software_name}")
        print(f"      Severidad: {severity_spanish.get(vuln_obj.severity, vuln_obj.severity)}")
        print(f"      Agente: {vuln_obj.agent_name} ({vuln_obj.agent_ip})")
        print(f"      Nuclei: {nuclei_status}")
        print(f"      Justificación: {vuln['reasoning']}")
        print()
    
    print("SUCCESS Proceso completado exitosamente!")
    print(f"STEP Revisa los reportes en {args.output_dir}/ para obtener detalles completos.")
    print(f"TEST_TUBE Usa los comandos en nuclei_commands_{timestamp}.json para validación.")

if __name__ == "__main__":
    main()

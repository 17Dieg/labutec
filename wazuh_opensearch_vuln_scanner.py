#!/usr/bin/env python3

import requests
import json
import argparse
import getpass
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhOpenSearch:
    def __init__(self, host, port=9200, username="admin", password="admin", verify_ssl=False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}:{port}"
    
    def search_vulnerabilities(self, query=None, size=10000):
        url = f"{self.base_url}/wazuh-states-vulnerabilities-*/_search"
        
        if query is None:
            query = {"match_all": {}}
        
        payload = {"query": query, "size": size}
        
        try:
            response = requests.get(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                headers={'Content-Type': 'application/json'},
                json=payload,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error consultando vulnerabilidades: {e}")
            return None

def print_vulnerability_summary(vulnerabilities):
    if not vulnerabilities or 'hits' not in vulnerabilities:
        print("No se encontraron vulnerabilidades")
        return
    
    hits = vulnerabilities['hits']['hits']
    total = vulnerabilities['hits']['total']['value']
    
    print(f"Total de vulnerabilidades encontradas: {total}")
    print("=" * 100)
    
    for i, hit in enumerate(hits, 1):
        source = hit['_source']
        print(f"\n[{i}] VULNERABILIDAD COMPLETA:")
        print(json.dumps(source, indent=2, ensure_ascii=False))
        print("=" * 100)

def main():
    parser = argparse.ArgumentParser(description='Escáner de vulnerabilidades Wazuh OpenSearch')
    parser.add_argument('--host', required=True, help='Host de OpenSearch')
    parser.add_argument('--user', required=True, help='Usuario de OpenSearch')
    parser.add_argument('--port', type=int, default=9200, help='Puerto de OpenSearch (default: 9200)')
    
    args = parser.parse_args()
    
    password = getpass.getpass("Ingrese la contraseña: ")
    
    opensearch = WazuhOpenSearch(args.host, args.port, args.user, password)
    
    print("Conectando a OpenSearch de Wazuh...")
    print("Obteniendo información del endpoint wazuh-states-vulnerabilities-*")
    print("=" * 100)
    
    all_vulns = opensearch.search_vulnerabilities()
    
    if all_vulns:
        print_vulnerability_summary(all_vulns)
        
        output_file = f"vulnerabilities_{args.host.replace('.', '_')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_vulns, f, indent=2, ensure_ascii=False)
        print(f"\nDatos guardados en: {output_file}")
    else:
        print("No se pudieron obtener datos del endpoint")

if __name__ == "__main__":
    main()

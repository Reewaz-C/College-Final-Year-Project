import asyncio
from zapv2 import ZAPv2
from typing import List, Dict

# Define function to initialize ZAP instance
def initialize_zap(api_key: str) -> ZAPv2:
    return ZAPv2(apikey=api_key)

# Define function to perform ZAP spider scan
async def perform_zap_spider_scan(zap: ZAPv2, url: str) -> int:
    spider_scan_id = zap.spider.scan(url)
    return spider_scan_id

# Define function to wait for ZAP spider scan to complete
async def wait_for_zap_spider_scan(zap: ZAPv2, scan_id: int) -> None:
    while int(zap.spider.status(scan_id)) < 100:
        await asyncio.sleep(5)

# Define function to perform ZAP active scan
async def perform_zap_active_scan(zap: ZAPv2, url: str) -> int:
    active_scan_id = zap.ascan.scan(url)
    return active_scan_id

# Define function to wait for ZAP active scan to complete
async def wait_for_zap_active_scan(zap: ZAPv2, scan_id: int) -> None:
    while int(zap.ascan.status(scan_id)) < 100:
        await asyncio.sleep(5)

# Define function to retrieve ZAP scan alerts
def retrieve_zap_alerts(zap: ZAPv2, base_url: str) -> List[Dict[str, str]]:
    return zap.core.alerts(baseurl=base_url)

# Define function to extract vulnerabilities from ZAP scan results
def extract_vulnerabilities(zap_alerts: List[Dict[str, str]]) -> List[Dict[str, str]]:
    vulnerabilities = []
    for alert in zap_alerts:
        vuln_details = {
            'Description': alert.get('description', ''),
            'URL': alert.get('url', ''),
            'Tags': ', '.join(alert.get('tags', {}).keys()),
            'Risk': alert.get('risk', ''),
            'Solution': alert.get('solution', ''),
            'Reference': alert.get('reference', ''),
            # Add more details if needed
        }
        vulnerabilities.append(vuln_details)
    return vulnerabilities

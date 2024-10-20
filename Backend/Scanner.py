import asyncio
import logging
import subprocess
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.edge.options import Options as EdgeOptions
from contextlib import asynccontextmanager
from bleach.sanitizer import Cleaner
from zapv2 import ZAPv2
from lxml import html
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import utils
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from bs4 import BeautifulSoup 
import re
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse
from pprint import pprint
import queue
import os
import sys
import datetime
import safety
from datetime import *
import socket
from ZAP_int import initialize_zap, perform_zap_spider_scan, wait_for_zap_spider_scan, \
    perform_zap_active_scan, wait_for_zap_active_scan, retrieve_zap_alerts, extract_vulnerabilities
from report_generation import generate_pdf_report

# Add the parent directory to the Python path
DB_path = os.path.abspath(r"D:\\class\\year 3\\FYP\\Development")
sys.path.insert(0, DB_path)

# Import the record_scan function from Database.py
from Database.scan import record_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create a message queue
message_queue = queue.Queue()

# initialize an HTTP session & set the browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

# Define configuration variables
YOUR_ZAP_API_KEY = "rlssc56bsj1m0vehdu0bngjaab"
EDGE_DRIVER_PATH = "D:\\class\\year 3\\FYP\\Development\\msedgedriver.exe"

# Define security headers to check for
security_headers = {
    "X-Frame-Options": r"(?i)DENY|SAMEORIGIN",
    "Content-Security-Policy": r"(?i).+",
}
# Define a cleaner for safe HTML parsing
cleaner = Cleaner()

#Funtion to scan SQL Injection
def get_all_forms(url):
        """Given a `url`, it returns all forms from the HTML content"""
        soup = bs(s.get(url).content, "html.parser")
        return soup.find_all("form")

def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False

# Function to send a message containing the URL to the GUI application
def send_url(url):
    message_queue.put(url)

def scan_sql_injection(url):
    try:
        # test on URL
        for c in "\"'":
            # add quote/double quote character to the URL
                    # add quote/double quote character to the URL
            new_url = f"{url}{c}"
            print("[!] Trying", new_url)
            # make the HTTP request
            res = s.get(new_url)
            if is_vulnerable(res):
                # SQL Injection detected on the URL itself, 
                # no need to proceed for extracting forms and submitting them
                print("[+] SQL Injection vulnerability detected, link:", new_url)
                return (True, new_url)

        # test on HTML forms
        forms = get_all_forms(url)
        print(f"[+] Detected {len(forms)} forms on {url}.")
        for form in forms:
            form_details = get_form_details(form)
            for c in "\"'":
                # the data body we
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        # any input form that is hidden or has some value,
                        # just use it in the form body
                        try:
                            data[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    elif input_tag["type"] != "submit":
                        # all others except submit, use some junk data with a special character
                        data[input_tag["name"]] = f"test{c}"
                # join the url with the action (form request URL)
                url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    res = s.post(url, data=data)
                elif form_details["method"] == "get":
                    res = s.get(url, params=data)
                # test whether the resulting page is vulnerable
                if is_vulnerable(res):
                    print("[+] SQL Injection vulnerability detected, link:", url)
                    print("[+] Form:")
                    pprint(form_details)
                    return (True, url)
        # If no vulnerability found
        print("[-] No SQL Injection vulnerability detected.")
        return (False, None)
    except Exception as e:
        print(f"Error during SQL injection scan: {e}")
        return (False, None)

def get_all_links(url):
    """Given a `url`, it returns all links from the HTML content"""
    try:
        soup = bs(s.get(url).content, "html.parser")
        return soup.find_all("a", href=True)
    except Exception as e:
        print(f"Error in get_all_links: {e}")
        return []

# Function to check for Broken Access Control vulnerability
def check_broken_access_control(url):
    try:
        links = get_all_links(url)
        if links:
            print(f"[+] Detected {len(links)} links on {url}.")
            for link in links:
                href = link["href"]
                if href.startswith(("http://", "https://")):
                    target_url = href
                else:
                    target_url = urljoin(url, href)
                response = s.get(target_url)
                if response.status_code != 200:
                    print(f"[-] Broken Access Control vulnerability detected at link: {target_url}")
                    return (True, f"Broken Access Control vulnerability detected at link: {target_url}")
        else:
            print("No links found on the page.")
            return (False, "No Broken Access Control vulnerability detected.")
    except Exception as e:
        print(f"Error in scan_broken_access_control: {e}")
        return (False, "Error occurred during scan.")
    return (False, "No Broken Access Control vulnerability detected.")

################################################################################################################

def check_security_misconfiguration(target_url):
    try:
        # Check for Security Misconfiguration vulnerability
        response_git = requests.get(f"{target_url}/.git/config", allow_redirects=True)
        response_env = requests.get(f"{target_url}/.env", allow_redirects=True)
        response_wp_config = requests.get(f"{target_url}/wp-config.php", allow_redirects=True)

        # Check .git configuration
        if response_git.status_code == 200:
            if "repositoryformatversion" in response_git.text.lower():
                return True, "Security Misconfiguration vulnerability detected: .git configuration exposed."
            else:
                indicative_strings = [
                    "repositoryformatversion",
                    "gitdir:",
                    "core.repositoryformatversion"
                ]
                for string in indicative_strings:
                    if string.lower() in response_git.text.lower():
                        return True, "Security Misconfiguration vulnerability detected: .git configuration may be exposed."
                
                # Check for directory listing
                if "/.git/" in response_git.url:
                    return True, "Security Misconfiguration vulnerability detected: Directory listing may be enabled for .git."

        # Check .env file
        if response_env.status_code == 200:
            return True, "Security Misconfiguration vulnerability detected: .env file exposed."

        # Check wp-config.php file
        if response_wp_config.status_code == 200:
            if "<?php" in response_wp_config.text:
                return True, "Security Misconfiguration vulnerability detected: wp-config.php file exposed."
        
        return False, "No Security Misconfiguration vulnerability detected."

    except requests.RequestException as e:
        logging.error(f"Error checking for security misconfigurations: {e}")
        return False, f"Error checking for security misconfigurations: {e}"
    except Exception as e:
        logging.error(f"Unexpected error checking for security misconfigurations: {e}")
        return False, f"Unexpected error checking for security misconfigurations: {e}"

################################################################################################################

# Function to check for Sensitive Data Exposure vulnerability / cryptographic failures
def check_sensitive_data_exposure_and_cryptographic_failures(target_url):
    try:
        # Make a GET request to access the passwords.txt file
        response = requests.get(target_url + "/passwords.txt")

        # Verify if the request was successful (status code 200)
        if response.status_code == 200:
            # Use BeautifulSoup to parse the HTML content
            soup = BeautifulSoup(response.content, 'html.parser')

            # Check if the response contains sensitive data
            sensitive_data_indicators = ["password", "credential", "secret"]
            for indicator in sensitive_data_indicators:
                if indicator.lower() in soup.get_text().lower():
                    return True, "Sensitive Data Exposure vulnerability detected: passwords.txt exposed."
            # If none of the sensitive data indicators are found
            return False, "No Sensitive Data Exposure vulnerability detected: passwords.txt not exposed."
        else:
            # Handle non-200 status code
            return False, "No Sensitive Data Exposure vulnerability detected: passwords.txt not found."

    except requests.RequestException as e:
        logging.error(f"Error checking for Sensitive Data Exposure vulnerability: {e}")
        return False, f"Error checking for Sensitive Data Exposure vulnerability: {e}"
    except Exception as e:
        logging.error(f"Unexpected error checking for Sensitive Data Exposure vulnerability: {e}")
        return False, f"Unexpected error checking for Sensitive Data Exposure vulnerability: {e}"
    
################################################################################################################
from typing import List, Tuple
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

def extract_js_libraries(html_content: str) -> List[str]:
    soup = BeautifulSoup(html_content, 'html.parser')
    scripts = soup.find_all('script', src=True)
    js_libraries = [script['src'] for script in scripts]
    return js_libraries

def scan_js_libraries(libraries: List[str]) -> List[str]:
    vulnerable_libraries = []
    for library in libraries:
        try:
            # Specify the full path to the npm executable
            npm_path = 'C:\\Program Files\\nodejs\\npm.cmd'
            result = subprocess.run([npm_path, 'audit', '--json', '--registry', 'https://registry.npmjs.org/', library], capture_output=True, text=True, check=True)
            if result.returncode == 0:
                audit_data = result.stdout
                if '"vulnerabilities":{}' not in audit_data:
                    vulnerable_libraries.append(library)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error scanning library {library}: {e}")
    return vulnerable_libraries

def detect_vulnerable_components(html_content: str) -> List[str]:
    vulnerable_components = []
    # Add code to detect vulnerable components in the HTML content
    # Example: Check for known vulnerable components or patterns
    if "<input type='password' value='" in html_content:
        vulnerable_components.append("Plaintext password storage")
    # Add more vulnerability detection logic here
    return vulnerable_components

def check_vulnerable_components(url: str) -> Tuple[List[str], List[str]]:
    try:
        response = requests.get(url)
        if response.status_code != 200:
            logging.error(f"Failed to access {url}. Status code: {response.status_code}")
            return [], []
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to access {url}. Error: {e}")
        return [], []

    js_libraries = extract_js_libraries(response.text)
    if not js_libraries:
        logging.info("No JavaScript libraries found on the provided URL.")
        return [], []

    vulnerable_libraries = scan_js_libraries(js_libraries)
    if not vulnerable_libraries:
        logging.info("No vulnerable JavaScript libraries found.")
    else:
        logging.info("Vulnerable JavaScript libraries found:")
        for vulnerable_library in vulnerable_libraries:
            logging.info(f"- {vulnerable_library}")

    vulnerable_components = detect_vulnerable_components(response.text)
    if not vulnerable_components:
        logging.info("No vulnerable components found.")
    else:
        logging.info("Vulnerable components found:")
        for vulnerable_component in vulnerable_components:
            logging.info(f"- {vulnerable_component}")

    return vulnerable_libraries, vulnerable_components

# Function to check for Identification and Authentication Failures vulnerability
def check_authentication_failures(url):
    try:
        session = requests.Session()
        response = session.get(url, allow_redirects=True)
        
        # Check for common authentication mechanisms
        if response.status_code == 401:
            print(f"Potential OWASP A07 vulnerability found (HTTP Basic Auth): {url}")
            return True, f"Potential OWASP A07 vulnerability found (HTTP Basic Auth)"
        elif response.status_code == 403:
            print(f"Potential OWASP A07 vulnerability found (HTTP Digest Auth): {url}")
            return True, f"Potential OWASP A07 vulnerability found (HTTP Digest Auth)"

        # Check for custom authentication mechanisms in response headers
        elif 'WWW-Authenticate' in response.headers:
            auth_headers = response.headers.get('WWW-Authenticate')
            if 'basic' in auth_headers.lower():
                print(f"Potential OWASP A07 vulnerability found (HTTP Basic Auth): {url}")
                return True, f"Potential OWASP A07 vulnerability found (HTTP Basic Auth)"
            elif 'digest' in auth_headers.lower():
                print(f"Potential OWASP A07 vulnerability found (HTTP Digest Auth): {url}")
                return True, f"Potential OWASP A07 vulnerability found (HTTP Digest Auth)"
            else:
                print(f"Potential OWASP A07 vulnerability found (Custom Auth): {url}")
                return True, f"Potential OWASP A07 vulnerability found (Custom Auth)"

        # Check for login forms that might not return a 401 or 403
        else:
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                if action and action != '#':
                    print(f"Potential OWASP A07 vulnerability found (Login Form): {url}")
                    return True, f"Potential OWASP A07 vulnerability found (Login Form)"
            return False, "No OWASP A07 vulnerability detected."

    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scanning {url}: {e}")
        return False, f"Error occurred while scanning {url}: {e}"

def check_session_management_vulnerabilities(url):
    try:
        session = requests.Session()
        response = session.get(url, allow_redirects=True)
        
        # Check for session fixation vulnerability
        if 'Set-Cookie' in response.headers:
            cookies = response.headers.get('Set-Cookie')
            if 'HttpOnly' not in cookies:
                print(f"Potential session fixation vulnerability found: {url}")
                return True, f"Potential session fixation vulnerability found"
        
        return False, "No session management vulnerabilities detected."

    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scanning {url}: {e}")
        return False, f"Error occurred while scanning {url}: {e}"

def check_brute_force_vulnerabilities(url):
    try:
        # Send multiple login attempts with different passwords
        login_url = url + "/login"  # Adjust the URL endpoint based on your application's login page
        for password in ["password1", "password2", "password3"]:
            session = requests.Session()
            data = {
                "username": "admin",
                "password": password
            }
            response = session.post(login_url, data=data)
            if response.status_code == 200:
                # Check for error message indicating failed login attempts
                if "Invalid username or password" in response.text:
                    print(f"Potential brute force attack vulnerability found: {url}")
                    return True, f"Potential brute force attack vulnerability found"
        
        return False, "No brute force attack vulnerabilities detected."

    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scanning {url}: {e}")
        return False, f"Error occurred while scanning {url}: {e}"

# Function to check for insecure design vulnerabilities
def check_insecure_design(target_url):
    try:
        # Validate the target URL
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return False, "Invalid target URL."

        # Check if the target URL is accessible
        try:
            socket.gethostbyname(parsed_url.netloc)
        except socket.gaierror:
            return False, f"Unable to resolve the hostname: {parsed_url.netloc}"

        # Make a request to the target URL to retrieve the HTML content
        start_time = datetime.now()
        response = requests.get(target_url, timeout=30)
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()

        # Check the response status code
        if response.status_code != 200:
            return False, f"Failed to retrieve content from {target_url}. Status code: {response.status_code}"

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extract JavaScript code from script tags
        scripts = soup.find_all('script')
        source_code = '\n'.join([script.get_text() for script in scripts])

        # Check for common indicators of insecure design patterns
        insecure_patterns = [
            r"eval\s*\(", r"system\s*\(", r"exec\s*\(", r"open\s*\(", r"pickle\.",
            r"os\.", r"subprocess\.", r"shutil\.", r"chmod\s*\(", r"chown\s*\("
        ]
        insecure_found = False
        insecure_details = []
        for pattern in insecure_patterns:
            if re.search(pattern, source_code):
                insecure_found = True
                insecure_details.append(f"Found insecure pattern: {pattern}")

        # Return the results
        if insecure_found:
            return True, insecure_details
        else:
            return False, "No insecure design patterns found."

    except requests.exceptions.Timeout:
        return False, f"Timed out while accessing {target_url}. Response time exceeded 30 seconds."
    except requests.exceptions.RequestException as e:
        return False, f"Error accessing the target URL: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"
    
#l###################################ogging and monitoring#########################
# Setting up logging
logging.basicConfig(filename='logging_monitoring_failure.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scrape_logs(url):
    if url is None:
        url = url  # Use the defined target URL
    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        soup = BeautifulSoup(response.text, 'html.parser')
        # Check if <pre> tag exists
        pre_tag = soup.find('pre')
        if pre_tag:
            log_data = pre_tag.text
            return log_data
        else:
            # If <pre> tag is not found, check for other common log-containing tags
            log_data = ''
            log_tags = soup.find_all(['code', 'textarea', 'div', 'span'])
            for tag in log_tags:
                if 'log' in tag.text.lower() or 'error' in tag.text.lower():
                    log_data += tag.text.strip() + '\n'
            if log_data:
                return log_data
            else:
                logging.error(f"Failed to find log data in the response from {url}")
                return None
    except requests.RequestException as e:
        logging.error(f"Error occurred while scraping logs from {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error occurred while scraping logs from {url}: {e}")
        return None

def analyze_logs(log_data):
    try:
        #  checking for known patterns indicating logging failure
        if log_data and 'ERROR' in log_data.upper():
            logging.info("Logging failure detected: Error entries found in logs")
            print("Logging failure detected: Error entries found in logs")
        elif log_data:
            logging.info("No logging failure detected")
            print("No logging failure detected")
        else:
            logging.error("No log data available for analysis")
            print("No log data available for analysis")
    except Exception as e:
        logging.error(f"Error occurred while analyzing logs: {e}")

#############################SSRF#########################################

def check_ssrf(url):
    try:
        # Validate the target URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return False, "Invalid target URL."

        # Check if the target URL is accessible
        try:
            socket.gethostbyname(parsed_url.netloc)
        except socket.gaierror:
            return False, f"Unable to resolve the hostname: {parsed_url.netloc}"

        # Make a request to the target URL with a timeout
        start_time = datetime.now()
        response = requests.get(url, allow_redirects=False, timeout=30)
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()

        # Check the response status code
        if response.status_code == 200:
            # Additional checks based on response content
            sensitive_data_found, sensitive_data_types = is_sensitive_data(response.text)
            if "internal" in response.text.lower():
                return True, f"SSRF vulnerability detected: {url} contains 'internal' keyword"
            elif sensitive_data_found:
                return True, f"SSRF vulnerability detected: {url} contains sensitive data ({', '.join(sensitive_data_types)})"
            else:
                return False, f"URL is accessible: {url}"
        else:
            return False, f"URL returned status code {response.status_code}: {url}"

    except requests.exceptions.Timeout:
        return False, f"Timed out while accessing {url}. Response time exceeded 30 seconds."
    except requests.exceptions.RequestException as e:
        return False, f"Error accessing URL: {url} - {e}"
    except Exception as e:
        return False, f"An unexpected error occurred: {e}"

def is_sensitive_data(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')

    sensitive_data_found = False
    sensitive_data_types = []

    # Look for specific tags or patterns indicating sensitive data
    if soup.find(re.compile('password', re.IGNORECASE)):
        sensitive_data_found = True
        sensitive_data_types.append('Password')
    if re.search(r'\b\d{4}-\d{4}-\d{4}-\d{4}\b', html_content):
        sensitive_data_found = True
        sensitive_data_types.append('Credit card number')
    if re.search(r'\b\d{3}-\d{2}-\d{4}\b', html_content):
        sensitive_data_found = True
        sensitive_data_types.append('Social Security number')
    if re.search(r'\b\d{10,}\b', html_content):
        sensitive_data_found = True
        sensitive_data_types.append('Bank account number')

    return sensitive_data_found, sensitive_data_types

def scan_ssrf(url):
    try:
        logging.info(f"Scanning for SSRF vulnerabilities at {url}...")
        ssrf_vulnerability_detected, ssrf_vulnerability_info = check_ssrf(url)
        if ssrf_vulnerability_detected:
            logging.warning(ssrf_vulnerability_info)
            return ssrf_vulnerability_info
        else:
            logging.info("No SSRF vulnerability detected.")
            return "No SSRF vulnerability detected."
    except Exception as e:
        logging.error(f"An error occurred during SSRF scanning: {e}")
        return f"An error occurred during SSRF scanning: {e}"
    
##################################################################################

def check_integrity_failures(url):
    try:
        # Validate the target URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return False, "Invalid target URL."

        # Check if the target URL is accessible
        try:
            socket.gethostbyname(parsed_url.netloc)
        except socket.gaierror:
            return False, f"Unable to resolve the hostname: {parsed_url.netloc}"

        # Make a request to the target URL with a timeout
        start_time = datetime.now()
        response = requests.get(url, timeout=30)
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()

        # Check the response status code
        response.raise_for_status()

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check for integrity failures in script tags
        integrity_failures = []
        scripts = soup.find_all('script')
        for script in scripts:
            integrity_attr = script.get('integrity')
            if integrity_attr:
                integrity_algorithm = re.search(r'(?<=\s)[a-zA-Z0-9_-]+(?=\s*;|$)', integrity_attr)
                if integrity_algorithm:
                    integrity_algorithm = integrity_algorithm.group(0)
                    if integrity_algorithm.lower() != 'sha256':
                        # Check if using SHA256 algorithm
                        integrity_failures.append({
                            "script_src": script.get('src'),
                            "integrity_algorithm": integrity_algorithm
                        })
                    else:
                        # Check if crossorigin attribute is set
                        crossorigin_attr = script.get('crossorigin')
                        if not crossorigin_attr:
                            integrity_failures.append({
                                "script_src": script.get('src'),
                                "integrity_algorithm": integrity_algorithm,
                                "issue": "Missing 'crossorigin' attribute"
                            })

        if integrity_failures:
            return True, "Integrity failures detected: " + str(integrity_failures)
        else:
            return False, "No integrity failures detected."

    except requests.exceptions.Timeout:
        return False, f"Timed out while accessing {url}. Response time exceeded 30 seconds."
    except requests.exceptions.RequestException as e:
        return False, f"Error fetching URL: {e}"
    except Exception as e:
        return False, f"An unexpected error occurred: {e}"

def scan_integrity_failures(url):
    try:
        logging.info(f"Scanning for Integrity Failures at {url}...")
        integrity_failures_detected, integrity_failures_info = check_integrity_failures(url)
        if integrity_failures_detected:
            logging.warning(integrity_failures_info)
            return integrity_failures_info
        else:
            logging.info("No Integrity Failures detected.")
            return "No Integrity Failures detected."
    except Exception as e:
        logging.error(f"An error occurred during Integrity Failures scanning: {e}")
        return f"An error occurred during Integrity Failures scanning: {e}"
    
###################################################################################
async def scan_page(url, driver, custom_checks=None):
        try:
            await driver.get(url)

            # Checking for missing security headers
            headers = {h.lower(): v for h, v in driver.execute_script("return window.performance.getEntriesByType('header')")[0].items()}
            missing_headers = [h for h in security_headers if h.lower() not in headers]
            if missing_headers:
                logging.warning(f"{url} is missing security headers: {missing_headers}")

            # Checking for forms without CSRF protection
            forms = driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                csrf_token = form.find_element(By.NAME, "csrfmiddlewaretoken")
                if not csrf_token:
                    logging.warning(f"{url} has a form without CSRF protection: {form.get_attribute('action')}")

            # Checking for direct object references in URLs
            html_content = driver.page_source
            tree = html.fromstring(cleaner.clean(html_content))
            links = tree.xpath("//a/@href")
            forms = tree.xpath("//form/@action")
            for link in links:
                if "=" in link and not link.startswith("/"):
                    logging.warning(f"{url} has a potential direct object reference: {link}")

            # Execute custom checks if provided
            if custom_checks:
                for check in custom_checks:
                    await check(url, driver)

        except (TimeoutException, WebDriverException) as e:
            logging.error(f"Error accessing {url}: {e}")

        finally:
            pass

#####################################################################################################

async def crawl(url, driver, max_depth=2, current_depth=0, custom_checks=None):
    if current_depth > max_depth or driver is None:  # Check if driver is None
        logging.error("Driver is None or max depth reached. Exiting crawl.")
        return
    try:
        logging.info(f"Crawling URL: {url}")
        await scan_page(url, driver, custom_checks)

        html_content = await driver.page_source()

        tree = html.fromstring(html_content)

        links = tree.xpath("//a/@href")

        logging.info(f"Found {len(links)} links on {url}")

        await asyncio.gather(*[crawl(link, driver, max_depth, current_depth + 1, custom_checks) for link in links])

    except (TimeoutException, WebDriverException) as e:
        logging.error(f"Error accessing {url}: {e}")

    except Exception as e:
        logging.error(f"Error during crawling: {e}")

    finally:
        pass

@asynccontextmanager
async def create_driver():
    driver = None
    service = None
    try:
        logging.info("Attempting to create Microsoft Edge Driver service...")
        service = EdgeService(executable_path=EDGE_DRIVER_PATH)
        service.start()
        logging.info("Microsoft Edge Driver service started successfully.")

        logging.info("Attempting to create Microsoft Edge Driver instance...")
        options = EdgeOptions()
        options.use_chromium = True  # Use Chromium-based Edge
        options.add_argument("--enable-chrome-browser-cloud-management")  # Add cloud management flag
        driver = webdriver.Edge(service=service, options=options)
        
        if driver:
            logging.info("Microsoft Edge Driver instance created successfully.")
            yield driver
        else:
            raise Exception("WebDriver instance is None")
    except Exception as e:
        logging.error(f"Error creating Microsoft Edge Driver: {e}")
        yield None  # Return None in case of error
    finally:
        if driver:
            driver.quit()
            logging.info("Microsoft Edge Driver instance quit.")
        if service:
            service.stop()
            logging.info("Microsoft Edge Driver service stopped.")
        
def check_owasp_api_security(url):
    security_headers = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy"
    ]

    try:
        # Validate URL format
        if not url.startswith("http"):
            return "Invalid URL format. URL must start with 'http' or 'https'."

        # Send GET request
        response = requests.get(url)

        # Check if the request was successful
        if response.ok:
            headers = response.headers

            # Check for missing security headers
            missing_headers = [h for h in security_headers if h not in headers]

            if missing_headers:
                return f"The API endpoint {url} is missing security headers: {missing_headers}"
            else:
                return f"The API endpoint {url} has all required security headers."
        else:
            return f"Failed to access the API endpoint {url}. Status code: {response.status_code}"

    # Handle specific exceptions
    except requests.exceptions.ConnectionError:
        return f"Failed to establish a connection to the API endpoint {url}."
    except requests.exceptions.RequestException as e:
        return f"An error occurred while checking the API security: {str(e)}"
    
# Function to extract vulnerabilities from ZAP scan alerts
def extract_vulnerabilities(zap_alerts):
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

async def check_function_1(url, driver):
    # Placeholder function for custom check 1
    logging.info(f"Performing custom check 1 for URL: {url}")

async def check_function_2(url, driver):
    # Placeholder function for custom check 2
    logging.info(f"Performing custom check 2 for URL: {url}")

async def scan_and_record(scan_name, result, vulnerability_detected):
    if result:
        date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        record_scan(scan_name, date_time, vulnerability_detected)
    else:
        date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        record_scan(scan_name, date_time, "No vulnerability detected")

async def scan(url):
    print(f"Scanning {url}...")
    try:
        scan_results = []
        
        # Create WebDriver instance
        async with create_driver() as driver:
            if driver is not None:
                await crawl(url, driver)  # Pass custom checks here
            else:
                logging.error("Failed to create Microsoft Edge Driver. Exiting...")
                return
    except Exception as e:
        logging.error(f"An error occurred: {e}")
            
    # Perform Injection vulnerability scan using requests
    injection_result, injection_info = scan_sql_injection(url)
    vulnerability_detected = "Vulnerability detected" if injection_result else "No vulnerability detected"
    scan_results.append(("Injection Vulnerability", injection_info if injection_result else "No Injection vulnerability detected."))

    # Perform insecure design scan
    insecure_design_result, insecure_design_info = check_insecure_design(url)
    scan_results.append(("Insecure Design Vulnerability", insecure_design_info if insecure_design_result else "No Insecure Design vulnerability detected."))
    vulnerability_detected = "Vulnerability detected" if insecure_design_result else "No vulnerability detected"

    # Perform Broken Access Control scan
    broken_access_control_result, broken_access_control_info = check_broken_access_control(url)
    scan_results.append(("Broken Access Control", broken_access_control_info if broken_access_control_result else "No Broken Access Control vulnerability detected."))
    vulnerability_detected = "Vulnerability detected" if broken_access_control_result else "No vulnerability detected"

    # Perform Security Misconfiguration scan
    security_misconfiguration_result, security_misconfiguration_info = check_security_misconfiguration(url)
    scan_results.append(("Security Misconfiguration", security_misconfiguration_info if security_misconfiguration_result else "No Security Misconfiguration vulnerability detected."))
    vulnerability_detected = "Vulnerability detected" if security_misconfiguration_result else "No vulnerability detected"

    # Perform Sensitive Data Exposure scan
    sensitive_data_exposure_result, sensitive_data_exposure_info = check_sensitive_data_exposure_and_cryptographic_failures(url)
    scan_results.append(("Sensitive Data Exposure", sensitive_data_exposure_info if sensitive_data_exposure_result else "No Sensitive Data Exposure vulnerability detected."))
    vulnerability_detected = "Vulnerability detected" if sensitive_data_exposure_result else "No vulnerability detected"

    # Perform Integrity failure scan
    integrity_failure_detected, integrity_failure_info = check_integrity_failures(url)
    scan_results.append(("Integrity Failure", integrity_failure_info if integrity_failure_detected else "No Integrity failure vulnerability detected."))
    vulnerability_detected = "Vulnerability detected" if integrity_failure_detected else "No vulnerability detected"

    # Perform Logging monitoring failure scan
    logging_monitoring_failure_info = scrape_logs(url)

    # Check if logs were successfully scraped
    if logging_monitoring_failure_info is not None and logging_monitoring_failure_info != "":
        # Analyze the scraped logs for logging monitoring failures
        analyze_logs(logging_monitoring_failure_info)
        
        # Append the result to the scan results
        scan_results.append(("Logging Monitoring Failure", logging_monitoring_failure_info))
        vulnerability_detected = "Vulnerability detected"
    else:
        # Append a message indicating that no logging monitoring failure vulnerability was detected
        scan_results.append(("Logging Monitoring Failure", "No Logging monitoring failure vulnerability detected."))
        vulnerability_detected = "No vulnerability detected"

    # Perform SSRF scan
    ssrf_vulnerability_detected, ssrf_vulnerability_info = check_ssrf(url)
    scan_results.append(("Server-Side Request Forgery (SSRF)", ssrf_vulnerability_info if ssrf_vulnerability_detected else "No SSRF vulnerability detected."))
    vulnerability_detected = "Vulnerability detected" if ssrf_vulnerability_detected else "No vulnerability detected"

    # Perform Vulnerable components scan
    vulnerable_libraries, vulnerable_info = check_vulnerable_components(url)
    vulnerability_detected = "Vulnerability detected" if vulnerable_libraries else "No vulnerability detected"
    scan_results.append(("Vulnerable Components", vulnerable_info if vulnerable_libraries else "No Vulnerable components vulnerability detected."))

    # Perform Authentication failure scan
    authentication_failure_detected, authentication_failure_info = check_authentication_failures(url)
    scan_results.append(("Authentication Failure", authentication_failure_info if authentication_failure_detected else "No Authentication failure vulnerability detected."))
    vulnerability_detected = "Vulnerability detected" if authentication_failure_detected else "No vulnerability detected"

    # Perform Brute force vulnerability scan
    brute_force_detected, brute_force_info = check_brute_force_vulnerabilities(url)
    scan_results.append(("Brute Force Vulnerability", brute_force_info if brute_force_detected else "No Brute force vulnerability detected."))
    vulnerability_detected = "Vulnerability detected" if brute_force_detected else vulnerability_detected

    # Perform Session management vulnerability scan
    session_management_detected, session_management_info = check_session_management_vulnerabilities(url)
    scan_results.append(("Session Management Vulnerability", session_management_info if session_management_detected else "No Session management vulnerability detected."))
    vulnerability_detected = "Vulnerability detected" if session_management_detected else vulnerability_detected

    # Perform OWASP API security check
    owasp_api_security_result = check_owasp_api_security(url)
    scan_results.append(("API security check", owasp_api_security_result if owasp_api_security_result else "No Authentication failure vulnerability detected."))
    vulnerability_detected = "Vulnerability detected" if owasp_api_security_result else "No vulnerability detected"

    # Insert scan result into database
    for scan_name, result in scan_results:
        await scan_and_record(scan_name, result, vulnerability_detected)

    # Initialize ZAP instance
    zap = initialize_zap(YOUR_ZAP_API_KEY)
    
    # Perform ZAP spider scan
    spider_scan_id = await perform_zap_spider_scan(zap, url)
    await wait_for_zap_spider_scan(zap, spider_scan_id)
    
    # Perform ZAP active scan
    active_scan_id = await perform_zap_active_scan(zap, url)
    await wait_for_zap_active_scan(zap, active_scan_id)
    
    # Retrieve ZAP alerts
    zap_alerts = retrieve_zap_alerts(zap, url)
    zap_results = extract_vulnerabilities(zap_alerts)
    
    # Generate PDF report
    generate_pdf_report(scan_results, zap_results, owasp_api_security_result)

    print
    print("Scan complete.")
    print("Scan results:", scan_results)

async def main(url):
    await scan(url)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: scanner.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    asyncio.run(main(url))
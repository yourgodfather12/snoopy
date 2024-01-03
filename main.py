import requests
from bs4 import BeautifulSoup
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityCheckFailed(Exception):
    pass

def perform_security_check(test_name, check_function):
    try:
        result = check_function()
        if result:
            logger.info(f"{test_name} - Failed: {result}")
            raise SecurityCheckFailed(f"{test_name} failed: {result}")
        else:
            logger.info(f"{test_name} - Passed")
    except SecurityCheckFailed as e:
        raise e
    except Exception as e:
        logger.warning(f"{test_name} - Check failed with error: {e}")
        raise SecurityCheckFailed(f"{test_name} check failed: {e}")

def check_information_disclosure(url):
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        # Look for specific keywords indicating sensitive information
        sensitive_keywords = ['password', 'username', 'private_key']
        for keyword in sensitive_keywords:
            if keyword in response.text.lower():
                return f"Suspected information disclosure: '{keyword}' found in response"
        return None
    except requests.RequestException as e:
        raise SecurityCheckFailed(f"Failed to fetch response: {e}")

def check_sql_injection(url):
    try:
        # Injecting SQL payload to check for vulnerability
        test_payload = "1' OR '1'='1"
        inject_url = f"{url}/search?id={test_payload}"
        response = requests.get(inject_url)
        if "error" in response.text:
            return "Vulnerable to SQL Injection"
        return None
    except requests.RequestException as e:
        raise SecurityCheckFailed(f"Failed SQL Injection test: {e}")

def check_xss_vulnerability(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        # Checking for script tags in the HTML content
        script_tags = soup.find_all('script')
        if script_tags:
            return f"Detected {len(script_tags)} <script> tags. Possible XSS Vulnerability."
        return None
    except requests.RequestException as e:
        raise SecurityCheckFailed(f"Failed XSS Vulnerability test: {e}")

def check_url_redirection(url):
    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code in [301, 302]:
            location = response.headers.get('Location')
            if location:
                return f"Detected redirection to: {location}"
            return "Detected redirection but no 'Location' header"
        return None
    except requests.RequestException as e:
        raise SecurityCheckFailed(f"Failed URL Redirection test: {e}")

def check_insecure_direct_object_references(url):
    try:
        # Check if endpoints provide unauthorized access to sensitive data
        response_1 = requests.get(url + "/data/1")
        response_2 = requests.get(url + "/data/2")
        if response_1.status_code != 200 or response_2.status_code != 200:
            return "Potential Insecure Direct Object References detected"
        return None
    except requests.RequestException as e:
        raise SecurityCheckFailed(f"Failed Insecure Direct Object References test: {e}")

def print_failed_tests(failed_tests):
    if failed_tests:
        print("\nFailed Tests:")
        for test in failed_tests:
            print(f"- {test}")

def main():
    url = input("Enter the URL to scan: ").strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    tests = [
        ("Information Disclosure Check", lambda: check_information_disclosure(url)),
        ("SQL Injection Check", lambda: check_sql_injection(url)),
        ("XSS Vulnerability Check", lambda: check_xss_vulnerability(url)),
        ("URL Redirection Check", lambda: check_url_redirection(url)),
        ("Insecure Direct Object References Check", lambda: check_insecure_direct_object_references(url))
    ]

    failed_tests = []

    for test_name, check_function in tests:
        try:
            perform_security_check(test_name, check_function)
        except SecurityCheckFailed as e:
            failed_tests.append(str(e))

    print_failed_tests(failed_tests)

if __name__ == "__main__":
    main()

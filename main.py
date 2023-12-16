import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
import nmap

failed_tests = []


def check_information_disclosure(url):
    try:
        response = requests.get(url)
        if response.ok:
            print(f"{Fore.GREEN}Information Disclosure Check - Status Code: {response.status_code}")
            print("Response Body:")
            print(response.text)
        else:
            print(f"{Fore.RED}Information Disclosure Check - Status Code: {response.status_code}")
            failed_tests.append("Information Disclosure Check")
    except requests.exceptions.MissingSchema:
        print(f"{Fore.RED}Invalid URL. Please include the scheme (http:// or https://) in the URL.")
        failed_tests.append("Information Disclosure Check")
    finally:
        print(Style.RESET_ALL)


def check_sql_injection(url):
    test_payloads = ["' OR '1'='1", "1'; DROP TABLE users; --", "' UNION SELECT '1",
                     "1' OR SLEEP(5)"]  # Expanded payloads
    vulnerable = False
    try:
        for payload in test_payloads:
            inject_url = f"{url}/search?id={payload}"
            response = requests.get(inject_url)
            if "error" in response.text:
                print(f"{Fore.RED}SQL Injection Check - Vulnerable to payload: {payload}")
                vulnerable = True
                failed_tests.append("SQL Injection Check")
                break
        if not vulnerable:
            print(f"{Fore.GREEN}SQL Injection Check - Not Vulnerable")
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}SQL Injection Check failed with error: {e}")
        failed_tests.append("SQL Injection Check")
    finally:
        print(Style.RESET_ALL)


def check_insecure_direct_object_references(url):
    try:
        response_1 = requests.get(url + "/data/1")
        response_2 = requests.get(url + "/data/2")

        if response_1.status_code == 200 and response_2.status_code == 200:
            print(f"{Fore.GREEN}Insecure Direct Object References Check - No potential IDOR detected")
        else:
            print(f"{Fore.RED}Insecure Direct Object References Check - Potential IDOR detected")
            failed_tests.append("Insecure Direct Object References Check")
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}Insecure Direct Object References Check failed with error: {e}")
        failed_tests.append("Insecure Direct Object References Check")
    finally:
        print(Style.RESET_ALL)


def check_xss_vulnerability(url):
    try:
        response = requests.get(url)
        if response.ok:
            soup = BeautifulSoup(response.text, 'html.parser')
            script_tags = soup.find_all('script')
            if script_tags:
                print(f"{Fore.RED}XSS Vulnerability Check - Detected {len(script_tags)} <script> tags")
                failed_tests.append("XSS Vulnerability Check")
            else:
                print(f"{Fore.GREEN}XSS Vulnerability Check - No <script> tags detected")
        else:
            print(f"{Fore.RED}XSS Vulnerability Check - Status Code: {response.status_code}")
            failed_tests.append("XSS Vulnerability Check")
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}XSS Vulnerability Check failed with error: {e}")
        failed_tests.append("XSS Vulnerability Check")
    finally:
        print(Style.RESET_ALL)


def check_url_redirection(url):
    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code in [301, 302]:
            location = response.headers.get('Location')
            if location:
                print(f"{Fore.RED}URL Redirection Check - Detected redirection to: {location}")
                failed_tests.append("URL Redirection Check")
            else:
                print(f"{Fore.RED}URL Redirection Check - Detected redirection but no 'Location' header")
                failed_tests.append("URL Redirection Check")
        else:
            print(f"{Fore.GREEN}URL Redirection Check - No redirection detected")
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}URL Redirection Check failed with error: {e}")
        failed_tests.append("URL Redirection Check")
    finally:
        print(Style.RESET_ALL)


def print_failed_tests():
    if failed_tests:
        print(f"\n{Style.BRIGHT}{Fore.RED}Failed Tests:")
        for test in failed_tests:
            print(f"- {test}")
        print(Style.RESET_ALL)


def run_nmap_scan(url):
    try:
        nm = nmap.PortScanner()
        nm.scan(url, arguments='-Pn')  # '-Pn' flag disables host discovery
        for host in nm.all_hosts():
            print(f"{Fore.GREEN}Nmap Scan Results for {host}:")
            print(nm[host].csv())
    except Exception as e:
        print(f"{Fore.RED}Error running Nmap scan: {e}")
        failed_tests.append("Nmap Scan")
    finally:
        print(Style.RESET_ALL)


def main():
    url = input("Enter the URL to scan: ")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    check_information_disclosure(url)
    check_sql_injection(url)
    check_xss_vulnerability(url)
    check_url_redirection(url)
    check_insecure_direct_object_references(url)

    run_nmap_scan(url)  # Include Nmap scan here

    print_failed_tests()


if __name__ == "__main__":
    main()

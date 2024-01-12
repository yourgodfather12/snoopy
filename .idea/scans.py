import requests
from bs4 import BeautifulSoup
import re
from utils import print_failed_tests


class SecurityCheckFailed(Exception):
    pass


# Update the make_request function in scans.py
def make_request(url, method='get', payload=None, headers=None, allow_redirects=True, session=None):
    try:
        if method.lower() == 'get':
            response = session.get(url, headers=headers, allow_redirects=allow_redirects)
        elif method.lower() == 'options':
            response = session.options(url, headers=headers)
        else:
            response = session.get(url, headers=headers, allow_redirects=allow_redirects)

        response.raise_for_status()
        return response
    except requests.RequestException as e:
        raise SecurityCheckFailed(f"Failed to fetch response from {url}: {e}")




def check_information_disclosure(url, session):
    try:
        response = make_request(url, headers={'User-Agent': 'Mozilla/5.0'}, session=session)

        sensitive_patterns = ['password', 'username', 'private_key']
        for pattern in sensitive_patterns:
            if pattern in response.text.lower():
                return f"Suspected information disclosure: '{pattern}' found in response"

        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_sql_injection(url, session):
    try:
        test_payload = "1' OR '1'='1"
        inject_url = f"{url}/search?id={test_payload}"
        response = make_request(inject_url, session=session)

        if "error" in response.text:
            return "Vulnerable to SQL Injection"

        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_xss_vulnerability(url, session):
    try:
        response = make_request(url, session=session)
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script')

        if script_tags:
            return f"Detected {len(script_tags)} <script> tags. Possible XSS Vulnerability."

        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_url_redirection(url, session):
    try:
        response = make_request(url, allow_redirects=False, session=session)

        if response.status_code in [301, 302]:
            location = response.headers.get('Location')
            if location:
                return f"Detected redirection to: {location}"
            return "Detected redirection but no 'Location' header"

        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_insecure_direct_object_references(url, session):
    try:
        response_1 = make_request(url + "/data/1", session=session)
        response_2 = make_request(url + "/data/2", session=session)
        if response_1.status_code != 200 or response_2.status_code != 200:
            return "Potential Insecure Direct Object References detected"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_sensitive_data_exposure(url, session):
    try:
        response = make_request(url, headers={'User-Agent': 'Mozilla/5.0'}, session=session)

        sensitive_patterns = ['credit card', 'ssn', 'api_key']
        for pattern in sensitive_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return f"Suspected sensitive data exposure: '{pattern}' found in response"

        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_authentication_bypass(url, session):
    try:
        response = make_request(url, session=session)
        if response.status_code == 200:
            return "Authentication Bypass vulnerability detected: Access granted without proper authentication."
        return None  # No vulnerability detected
    except SecurityCheckFailed as e:
        return str(e)


def check_security_headers(url, session):
    try:
        response = make_request(url, method='head', session=session)
        security_headers = response.headers
        if 'Content-Security-Policy' not in security_headers:
            return "Content-Security-Policy header is missing"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_error_handling(url, session):
    try:
        response = make_request(url + "/invalid_endpoint", session=session)
        if "404" not in response.text:
            return "Error handling might reveal sensitive information"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_cross_origin_resource_sharing(url, session):
    try:
        response = make_request(url, method='options', session=session)
        if 'Access-Control-Allow-Origin' not in response.headers:
            return "Cross-Origin Resource Sharing (CORS) is not properly configured"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_directory_listing(url, session):
    try:
        response = make_request(url, session=session)
        if response.status_code == 200 and "Index of /" in response.text:
            return "Directory listing enabled"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_http_methods(url, session):
    try:
        response = make_request(url, method='options', session=session)
        allowed_methods = response.headers.get('Allow')
        if allowed_methods and ('PUT' in allowed_methods or 'DELETE' in allowed_methods):
            return f"Unsafe HTTP methods allowed: {allowed_methods}"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_tls_configuration(url, session):
    try:
        response = make_request(url, session=session)
        cipher = response.connection.cipher() if hasattr(response.connection, 'cipher') else None
        tls_version = response.connection.tls_version if hasattr(response.connection, 'tls_version') else None
        if cipher and tls_version:
            return f"TLS version: {tls_version}, Cipher: {cipher}"
        return None
    except SecurityCheckFailed as e:
        return str(e)



def check_jwt_security(url, session):
    try:
        response = make_request(url, session=session)
        if 'Authorization' in response.headers:
            token = response.headers.get('Authorization').split(' ')[1]
            parts = token.split('.')
            if len(parts) != 3:
                return "Invalid JWT format"
            return None
        return "No JWT token found"
    except SecurityCheckFailed as e:
        return str(e)


def check_server_information(url, session):
    try:
        response = make_request(url, session=session)
        server_header = response.headers.get('Server')
        if server_header:
            return f"Server information exposed: {server_header}"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_clickjacking_vulnerability(url, session):
    try:
        response = make_request(url, session=session)
        if 'X-Frame-Options' not in response.headers:
            return "Vulnerable to Clickjacking"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_cookie_security(url, session):
    try:
        response = make_request(url, session=session)
        cookies = response.cookies
        if any(cookie.secure for cookie in cookies):
            return "Insecure cookies detected"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_cors_policy(url, session):
    try:
        response = make_request(url, session=session)
        policy_header = response.headers.get('Access-Control-Allow-Origin')
        if policy_header and policy_header != '*':
            return f"Specific CORS policy configured: {policy_header}"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def check_server_side_template_injection(url, session):
    try:
        payload = '{{7*7}}'
        inject_url = f"{url}/search?q={payload}"
        response = make_request(inject_url, session=session)
        if '49' in response.text:
            return "Vulnerable to Server-Side Template Injection"
        return None
    except SecurityCheckFailed as e:
        return str(e)


def perform_security_checks(url, session):
    failed_tests = []

    try:
        failed_tests.append(check_information_disclosure(url, session))
    except SecurityCheckFailed as e:
        failed_tests.append(str(e))

    # Add other security checks here
    failed_tests.append(check_sql_injection(url, session))
    failed_tests.append(check_xss_vulnerability(url, session))
    failed_tests.append(check_url_redirection(url, session))
    failed_tests.append(check_insecure_direct_object_references(url, session))
    failed_tests.append(check_sensitive_data_exposure(url, session))
    failed_tests.append(check_authentication_bypass(url, session))
    failed_tests.append(check_security_headers(url, session))
    failed_tests.append(check_error_handling(url, session))
    failed_tests.append(check_cross_origin_resource_sharing(url, session))
    failed_tests.append(check_directory_listing(url, session))
    failed_tests.append(check_http_methods(url, session))
    failed_tests.append(check_tls_configuration(url, session))
    failed_tests.append(check_jwt_security(url, session))
    failed_tests.append(check_server_information(url, session))
    failed_tests.append(check_clickjacking_vulnerability(url, session))
    failed_tests.append(check_cookie_security(url, session))
    failed_tests.append(check_cors_policy(url, session))
    failed_tests.append(check_server_side_template_injection(url, session))

    print_failed_tests([test for test in failed_tests if test])


if __name__ == "__main__":
    # Example usage:
    target_url = "https://example.com"
    with requests.Session() as session:
        perform_security_checks(target_url, session)

import logging
import time
import requests

from scans import (
    check_information_disclosure,
    check_sql_injection,
    check_xss_vulnerability,
    check_url_redirection,
    check_insecure_direct_object_references,
    check_sensitive_data_exposure,
    check_authentication_bypass,
    check_security_headers,
    check_error_handling,
    check_cross_origin_resource_sharing,
    check_directory_listing,
    check_http_methods,
    check_tls_configuration,
    check_jwt_security,
    check_server_information,
    check_clickjacking_vulnerability,
    check_cookie_security,
    check_cors_policy,
    check_server_side_template_injection
)

from utils import print_failed_tests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityCheckFailed(Exception):
    def __init__(self, test_name, details):
        super().__init__(f"{test_name} failed: {details}")
        self.test_name = test_name
        self.details = details


def perform_security_check(test_name, check_function, url, session):
    try:
        result = check_function(url, session)
        if result:
            logger.info(f"{test_name} - Failed: {result}")
            raise SecurityCheckFailed(test_name, details=result)
        else:
            logger.info(f"{test_name} - Passed")
    except SecurityCheckFailed as e:
        raise e
    except Exception as e:
        logger.warning(f"{test_name} - Check failed with error: {e}")
        raise SecurityCheckFailed(test_name, details=str(e))


def get_validated_url():
    while True:
        url = input("Enter the URL to scan: ").strip()

        if url.startswith(("http://", "https://")):
            break
        else:
            print("Invalid URL format. Please include 'http://' or 'https://'.")

    return url


def run_security_checks(url, session):
    tests = [
        ("Information Disclosure Check", check_information_disclosure),
        ("SQL Injection Check", check_sql_injection),
        ("XSS Vulnerability Check", check_xss_vulnerability),
        ("URL Redirection Check", check_url_redirection),
        ("Insecure Direct Object References Check", check_insecure_direct_object_references),
        ("Sensitive Data Exposure Check", check_sensitive_data_exposure),
        ("Authentication Bypass Check", check_authentication_bypass),
        ("Security Headers Check", check_security_headers),
        ("Error Handling Check", check_error_handling),
        ("Cross-Origin Resource Sharing Check", check_cross_origin_resource_sharing),
        ("Directory Listing Check", check_directory_listing),
        ("HTTP Methods Check", check_http_methods),
        ("TLS Configuration Check", check_tls_configuration),
        ("JWT Security Check", check_jwt_security),
        ("Server Information Check", check_server_information),
        ("Clickjacking Vulnerability Check", check_clickjacking_vulnerability),
        ("Cookie Security Check", check_cookie_security),
        ("CORS Policy Check", check_cors_policy),
        ("Server-Side Template Injection Check", check_server_side_template_injection)
    ]

    failed_tests = []

    for test_name, check_function in tests:
        try:
            perform_security_check(test_name, check_function, url, session)
            # Introduce a delay between checks to avoid potential rate-limiting or server restrictions
            time.sleep(2)
        except SecurityCheckFailed as e:
            failed_tests.append(e)
        except Exception as e:
            logger.warning(f"An unexpected error occurred during {test_name} check: {e}")

    return failed_tests


def main():
    try:
        url = get_validated_url()

        # Set up a session with headers to handle 403 Forbidden errors
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/91.0.4472.124 Safari/537.3'
        }
        with requests.Session() as session:
            session.headers.update(headers)
            failed_tests = run_security_checks(url, session)

        print_failed_tests(failed_tests)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()

This tool is used to scan the URL given for various vulnerabilities listed below 

- Information Disclosure Check: Looks for sensitive information like passwords, usernames, or private keys in the webpage content.
- SQL Injection Check: Tests if the website is vulnerable to SQL injection attacks.
- XSS Vulnerability Check: Checks for potential Cross-Site Scripting vulnerabilities.
- URL Redirection Check: Examines if the URL redirects to other locations.
- Insecure Direct Object References Check: Detects potential insecure direct object references.
- Sensitive Data Exposure Check: Looks for patterns indicating exposure of sensitive data like credit card numbers, social security numbers, or API keys.
- Authentication Bypass Check: Placeholder function that doesn't perform the check.
- Security Headers Check: Verifies the presence of security headers, focusing on the Content-Security-Policy header.
- Error Handling Check: Analyzes how error handling is managed by the server, particularly when encountering a 404 (Not Found) error.

To run this tool use the command 
"python3 main.py" and then enter the URL you want to scan. you do not have to put "https" or "http". URL's such as "fuckoff.com" will suffice  

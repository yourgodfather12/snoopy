This tool is used to scan the URL given for various vulnerabilities listed below 

1. Information Disclosure Check: Looks for sensitive information like 'password', 'username', or 'private_key' in the HTTP response.
2. SQL Injection Check: Tests if the web application is vulnerable to SQL injection using a test payload.
3. XSS (Cross-Site Scripting) Vulnerability Check: Analyzes the HTML response for the presence of <script> tags, indicating a possible XSS vulnerability.
4. URL Redirection Check: Verifies if the web application redirects properly and checks for potential security issues.
5. Insecure Direct Object References Check: Tests if there are potential insecure direct object references by making requests to different data endpoints.
6. Sensitive Data Exposure Check: Searches for patterns related to sensitive data like 'credit card', 'ssn', or 'api_key' in the HTTP response.
7. Authentication Bypass Check: Checks if the web application allows access without proper authentication.
8. Security Headers Check: Verifies if essential security headers, such as 'Content-Security-Policy', are present in the HTTP response.
9. Error Handling Check: Tests if error handling might reveal sensitive information.
10. Cross-Origin Resource Sharing (CORS) Check: Examines if CORS is properly configured in the web application.
11. Directory Listing Check: Checks if directory listing is enabled on the server.
12. HTTP Methods Check: Inspects if unsafe HTTP methods like 'PUT' or 'DELETE' are allowed.
13. TLS (Transport Layer Security) Configuration Check: Checks the TLS version and cipher used in the connection.
14. JWT (JSON Web Token) Security Check: Verifies the format of JWT tokens in the 'Authorization' header.
15. Server Information Exposure Check: Checks if server information is exposed in the HTTP response.
16. Clickjacking Vulnerability Check: Checks if the web application is vulnerable to clickjacking.
17. Cookie Security Check: Examines the security of cookies, looking for insecure settings.
18. CORS Policy Check: Verifies if a specific CORS policy is configured.
19. Server-Side Template Injection Check: Tests if the web application is vulnerable to server-side template injection.

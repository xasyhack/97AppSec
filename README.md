<img src="https://img3.od-cdn.com/ImageType-100/2858-1/%7B4D87366A-B490-40C1-9DCE-7FDBC9244F1F%7DIMG100.JPG" width="200"/>

[Secure Vibe Coding Guide]([https://cloudsecurityalliance.org/rails/active_storage/blobs/redirect/eyJfcmFpbHMiOnsibWVzc2FnZSI6IkJBaHBBdk5MIiwiZXhwIjpudWxsLCJwdXIiOiJibG9iX2lkIn19--7b3f54858a71571f11d20064f10de24f74cd7d86/DevSecOps-SDLC.png](https://cloudsecurityalliance.org/blog/2025/04/09/secure-vibe-coding-guide))

# Best Practices in Application Security

## Code Scanning and Reviews
- Detect improper configurations
- Identify poor programming practices
- Prevent Remote Code Execution (RCE)
- Catch SQL injection, command injection
- Mitigate Cross-Site Scripting (XSS)
- Prevent Cross-Site Request Forgery (CSRF)
- Fix broken authentication and session management
- Avoid weak key generation
- Ensure proper password hashing
- Remove hardcoded credentials
- Manage system resources properly
- Eliminate business logic flaws
- Restrict XML External Entity (XXE) references
- Prevent path traversal attacks
- Handle null pointer dereferencing
- Avoid Insecure Direct Object References (IDOR)
- Protect against buffer overflows
- Secure cryptographic storage
- Implement proper authorization controls

## AI for Better Detection and Automation
- Automate false positive triage in vulnerability scanners
- Detect anomalies using machine learning
- Leverage LLMs for secure code suggestions and documentation
- Use AI for malware analysis and threat detection

## Secure Coding Standards and Training
- Follow OWASP Top 10 and SEI CERT guidelines
- Conduct regular secure coding training
- Promote secure design patterns (e.g., input validation, output encoding)

## Threat Modeling
- Perform early in the SDLC
- Use STRIDE, PASTA, or tool-based modeling (e.g., OWASP Threat Dragon)
- Reassess with major design changes

## Shift-Left Security (DevSecOps)
- Integrate SAST, DAST, SCA into CI/CD
- Scan IaC templates and secrets during build
- Automate policy enforcement at commit and deploy stages

## Authentication & Authorization Best Practices
- Use OAuth 2.0, OpenID Connect, SAML
- Enforce multi-factor authentication (MFA)
- Apply least privilege using RBAC or ABAC
- Regularly rotate API keys and secrets

## Security Testing (Manual & Automated)
- Perform penetration and fuzz testing
- Include business logic and abuse-case testing
- Use RASP and runtime monitoring tools

## Secrets Management
- Store secrets in vaults (e.g., HashiCorp Vault, AWS Secrets Manager)
- Prevent credentials from being committed to repos
- Use CI/CD scanning tools like TruffleHog or GitGuardian

## Data Protection & Privacy
- Encrypt data in transit and at rest (TLS 1.3, AES-256)
- Apply data classification and redaction
- Comply with GDPR, CCPA, and other regulations

## Logging and Monitoring
- Capture and centralize security-relevant logs
- Use SIEM for analysis and alerting
- Monitor for anomalies and threat behavior

## Incident Response Preparedness
- Define and test incident response procedures
- Ensure application logs are integrated into IR tools
- Establish communication and escalation plans

# Secure code for tomorrow tech
- secure coding standards:  Open Web Application Security Project (OWASP) Top 10; CWE/SANS Top 25; least privilege, defense in depth, secure by default
- secure development life cycle: threat modeling, static analysis security testing in code, dynamic analysis in running app, automate processes such as policy compliance checks, dependency upgrades, credential rotation
- framework: Django for Python, Express for Node.js, Laravel for PHP 
- never trust inputs: Validate and sanitize, zero trust, limit exppsure, escape outputs
- Promote a culture of security: training, mentoring, incentives, and leading by example, providing useful security libraries, user-friendly tools, and clear guidance
- Prioritize appropriately: significant risks based on your threat model
- Long view: designs that are adaptable, resilient, and sustainable
- Stay current: Monitor emerging threats, revisit past assumptions, keep your skills sharp
- Teach others what you know: mentoring, code reviews, organizational training, publications and speak
- app sec activities: governance, finding security problems, fixing security problems, preventing security problems

# Modern application traits
- Components: Software bill of materials (SBOM) - nested libraries, components, and dependencies
- Infrastrucuture: Cloud-native env (AWS, Azure, GCP), containers, Kubernetes, and serverless 
- Automation: infrastructure as code (Terraform, CloudFormation)
- Architecure: microservices
- Enterprise SSO: Okta, Ping Identity, OneLogin
- API endpoints and external integrations: SAML, OAuth, OIDC
- Middleware and communication channels: message brokers (Kafka, RabbitMQ), service meshes (lstio), REST/gRPC APIs
- Logs monitoring: Prometheus, Grafana, ELK Stack, Datadog, or OpenTelemetry
- CI/CD pipeline: GitHub Actions, GitLab CI, Jenkins, or CircleCI
- Security: SAST, DAST, dependency scanning, and policy enforcement (“shift left”)
- Identity: Zero trust, IAM policies, workload identity, mTLS, RBAC, and ABAC
- Edge services & CDN integration: Cloudflare, Akamai, or Fastly for caching, routing, and web protection (WAF, DDoS protection, TLS termination, and bot mitigation).

# AppSec program
- SSDLC: communicate policy or standing
- Threat modeling: guide the architecture and security controls implemented
- Automation: integration, testing, deployment, software delivery
- Define the SSDLC governance process: Security architecture review in the design phase, a shift left
- API security: authenticaiton ,authorization, encryption
- Continuously train developers

# Secure SDLC
- Mindset: playbook, do you see what happened, scope (purpose of product), secure coding practices, data exposure and minimization, least priviledge and infra security, security tools and deployment, patch management, app monitoring and alerting, user training and awareness, endpoint security, incident response
- Automating Risk calculation: continuous application risk evaluation (CARE). Nature of app (data classification/compliance and regulation requirement), how is it built/maintained (tech stack), who is building and maintaining (experience of dev team)
- DevSecOps: Collaboration and Shared Responsibility, CI/CD, Threat Modeling and Risk Assessment, Automated Security Testing (SAST, DAST, SCA), Secure Configuuration and Secrets Management, Monitoring, Logging, and Incident Response
- Great SSDLC program: think (vision, strategic, customer feedback, driver, platform engineering), act (automation at all stages, threat detection, vulnerability management, CBA), persevere against challenge (lack of time, standarization, tech skills)
- CI/CI pipeline: run less than 10 mins, run for every commit, auto raised with engineer and into ticketing system, allow exceptions specific to env
- Serverless app: event driven, composed of multiple functions that are executed independently and asynchronously, multitenant cloud service susceptible to security risks (external, internal)
  - authentication and authorization
  - encryption (in transit and at rest): certs, encryption algorithms, secure key management
  - access controls
  - monitoring and loggin gmechanisms
  - testing and validation 
- Offensive security to defend: diff focus of developers and hackers (vulnerabilities, data exfiltration, how to manipulate user), response messages, API endpoints, admin features
- Cloud Era：secure config, continuous logging and monitoring, data protection in multitenant env (data isolation, encryption, access control and authentication, vulnerability managment, security monitoring, logggin, contractual agreement, regular security assessment), adopt clod access security brokers (data encryption, access control, threat prevention)
- Code Provenance/ownership: code signing, require verified commits, maintain audit logs and commit history, SBOMS to track components and dependencies (Syft, cycloneDx, Anchore, Trivy), tag builds and artifacts with Metadata, use immutable infra & images, source dependencies from approved respositories, doc provenance polices, developer identity & access control (SSO/MFA, RBAC)

# Data Security & Privacy
- Passwordless: defeat attack of brute force, phishing, password spray, dictionary attack. E.g mobile devices (fingerprint, face recognition, etc.), Touch ID for MacOS, and Windows Hello on Microsoft
- Securing DB: restrict root account, audit account permission, remove accounts that are no longer needed, password rotation
- DataSecOps: SOC, DevSecOps, Data privacy, Chaso engineering, data governance (polices, procedures, role), data quality (incident counts, response and resolution times, query performance), data classification 
- Governance: lvels of access based on user needs
- Protect sensitive data：key management (generation, exchange, storage, use, crypto-shredding, replacemen tof encryption keys), KSM, HSM, TPM
- Data-Flow Analysis  
- Privacy Paradigm: data ownership, Privacy-enhancing technologies (PETs), consent, Data Minimization and Purpose Limitation, decentralized data storage, privacy by design
- Quantum-Safe Encryption: quantum computers potentially breaks asymmetric encryption RSA & ECC (SSL/TLS, digital signatures, secure key exchange to ensure integrity and confidentiality of data). Look for quantum random number generators (QRNGs) generate truly random numbers that are unpredictable and nonreproducible,

# Code Scanning & Testing
- SCA: analyzing dependency manifest files to identify vulnerabilities associated with the included package.
  - Call graph–based based SCA pinpointing the potential exploited code
  - Runtime SCA analyzes software dependencies in real time
- App security testing
  - SAST: early detection (development phase), scan large codebased, high FP, apply on CI/CD pipelines
  - DAST: Realistic testing, runtime context, low FP, late detection, Incomprehensive coverage, apply on testing env
  - SCA: identification of known vulnerabilities in third-party libraries, open-source components, high coverage of commonly used libraries, often relies on CVEs, quick feedback, and easy integration into CI/CD pipelines, apply on development phase and continuous monitoring for updates
  - IAST: hybrid of SAST & DASDT, more accurate identification of vulnerabilities, deeper insight, Performance overhead, Deployment complexity, apply on staging env
- WAF: analyzing incoming traffic and filtering out malicious requests and attacks. Advantages of Layered defense, Ease of deployment, Signature-based protection, performance. Downsite of tuning, alert fatigue, limited context
- RASP: monitors the application’s behavior for suspicious activities. Advantages of Deeper contextual insights and accurate results, real-time protection and zero-day protection, Little to no tuning required. Downsite of performance, Integration challenges, need framework knowledge
- Zero Trust Software Architecture: identitity access, never trust data, Proactively test for security misconfigurations, STRIDE reduce attack surfaces
- CI/CD: risks include code injection, Secret/credential hygiene, Misconfiguration. Hyginene steps include access control to acccess pipeline, KMS or Key vault to protect credential, secure build env, code review, security best practices (password management, least privilege access, and regular software updates)

# Vulnerability Management
- Bug bounty program: Use an existing platform, Implement guardrails, Define payouts, Test in production
- Modern vulnerability management approach (Exploit Prediction Scoring System (EPSS)) https://www.first.org/epss/
  - Gathers data from vulnerability databases, threat intelligence, and exploit occurrences
  - Analyzes data using ML to identify exploitation patterns
  - Continuously refreshes data for current threat landscape
  - exploitability, exploit code availability, and software popularity.
  - Assigns probability scores
  - scores based on specific network environments and exposure levels.
  - Displays exploitation activity as evidence that exploitation of a vulnerability was attempted
- Top 25 parameters of vulnerability
  - XSS: inject malicious scripts in parameters ~ q, s, search, id, lang, keyword, query, apge, year, email, name, p
  - SSRF: manipulation of server-side requests to gain unauthorized acces to internal resources ~ dest, redirect, uri, path, data, reference, site, html, val
  - local file inclusion (LFI): unauthorized access to critical files ~ cat, dir, action, date, file, path, folder, include, page, inc
  - SQL: extract sensitive data ~ id, page, dir, search, category, file, url, lang, ref, title
  - Remote code execution (RCE): execute arbitrary code and compromise system security ~ cmd, exec, ping, query, code, process
  - open redirect: direct users to harmful website ~ next, url, target, dest, redirect_url

# Software Supply Chain
- selecting Open Source dependencies: review public vulnerability history, evaluate the community, analyze the frequency of releases, check the engineering practices, check for licensing, auditing and hardening, staying current with vulnerability management (monitor mailing list and securiyt advisories, inventory in SBOM, security assessment, remediation plan)
- Open source software (OSS): security policy for OSS, assess the security of OSS, regular security audit, patch management, secure coding practices, monitoring and analyze potential security threats, participate in OSS communication forum
- vendor management: CISO to CISO meeting, annual review to discuss service level/quality/cybersecurity, monitor the supplier for any changes in business health and cyberseuciry posture
- Open Source AI/ML: CI/CD for AL and ML, SBOM, auditing and verification, community collaboration
- SBOM: building transparency
- Secure software supply chain: build provenance.

# Threat Modeling

| Phase       | Developer                                                             |
|-------------|-----------------------------------------------------------------------|
| Design      | Use a mature authentication system                                   |
| Design      | Use a mature authorization system                                    |
| Design      | Use a mature session management system                               |
| Design      | Use good secrets management                                          |
| Development | Add application throttling for all inputs                            |
| Development | Use mature input sanitization libraries for all inputs              |
| Development | Use mature crypto libraries                                          |
| Development | Use automated documentation practices                                |
| Testing     | Use the latest version of dependencies                               |
| Maintenance | Continuous training on secure coding practices                       |

| Phase       | Infra team                                                            |
|-------------|-----------------------------------------------------------------------|
| Design      | Maintain optimal blast radius                                         |
| Deployment  | Enforce TLS 1.2+ on all data flows                                    |
| Maintenance | Maintain security agent installs                                      |
| Maintenance | Maintain mature accounting operations                                |
| Maintenance | Encrypt data at rest                                                  |
| Maintenance | Use least privilege design                                            |
| Maintenance | Tune boundary devices                                                 |
| Maintenance | Harden all computation systems                                        |
| Maintenance | Maintain mature authentication systems                                |
| Maintenance | Maintain attack surface reduction operations                          |
| Maintenance | Maintain proper secrets hygiene                                       |


- Threat model
  - What are we working on
  - What can go wrong
  - What are we going to do about it?
  - Did we do a good enough job
- OWASP Insecure Design： top 5 risky changes ~ new endpoints, changes in data flow, altered trust boundaries, misconfig, deprecated libraries. Toxic combination: secrets to access AWS in a public repository, internet facing API that exposed PII data/missing input validation, CI/CD misconfiguration
- Attack models in SSDLC
  - Define product security requirements
  - Threat model the product and identify security controls.
  - Configure scanners to identify vulnerabilities in code
  - Pen testing

# Threat Intelligence & Incident Response
- DoS
- Botnets: third party threat intelligence tools, automated web searches, regex patterns, open source vulnerability scanners scraping, vulnerability databas, API calls. Shifted focus to non-CVE exploits of misconfigur
- Credential stuffing: stealing compromised credentials gained from an exposed database
- SANS IR life cycle
  - Preparation: how and when to classify an incident before it has occurred
  - Identification: detecting deviations from normal operations
  - Containment: disabling network access to systems
  - Eradication: rmoval of any malicious software from systems so no further damage is done.
  - Recovery: patch
  - Lessons learned
- Threat intelligence: Tactics, Techniques, and Procedures (TTPs). Sources: OSINT, cyber threat intelligence feeds, idustry-specific threat-sharing groups, dark web. A robust threat intelligence program should include a detailed analysis of the TTPs used by threat actors and provide actionable insights on how to counter them. 

# Mobile Security
- Best practices
  - fundamentals: code review, examining & documenting ALL API endpoints, revising info in logs, remove all test code, check config
  - Privacy act: data breach response plan, third-party service privacy compliance, Secure data transfers, Enable user rights, robust encryption, secure authentication and authorization, Collect only the data necessary
- Containerization: Separation between applications is done using virtualization or application sandboxing technique. Eg enterprise mobility management (EMM) or mobile device management (MDM)

# API Security
- JWE Encryption
  - JWTs are Base64 URL-encoded objects that can optionally be signed via JSON Web Signatures (JWS).
  - encoded header:
    ```
    eyJhbGciOi.[header]JSU0EtT0FFUC0yNTYiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwia
    WF0IjoxNTg1NzAyMjg1LCJ0eXAiOiJKV1QifQ.[CEK]HY8160chJ4VeWWQzPZzehFApkhUzhoL
    Hg9pUvnnWRiW33bvsYUBNV3dKCLrV_KRosXnbnYgLgOp5nRV3Wj9GG2ZcEniJzRzZpDlgvN
    0lmNwVRS1kiNw3s7-5eK0kmZz2hsVzGnvPS5Ng9-tzABVyerDi7USmp59lsfqtFCQHRk6ha
    AW7PZ-YpynRWXl4mDseLKgwsGJBxiW-eymoIMJeOUENWbtiJXfEz5vVB1fhCPQo7INPiQTC
    N9DPhzV2i4fES7cJZkDBO5SiSBZGgt_xTaIej0ZRdRkZjkqYUJtCJvCEeEGISSo9aM7UBEq
    3wk_WIAGKU3xCuashZOhHQrw7gL9AeY4AXZQzph4Ny134fdZakJjWwJmyZD3EkfzVlM0_lW
    jGUsje1POkZKoyej2OMF3bGK2_OPaMySZrvwYMRdEtZiQPGHFRJS42EYctcImuLHXt9KGa4
    wBtsur5V-_ioaePaSAKv3es6xQTmdYRMDCVPZjckD7Gsy2ZQHAI9epN8zQttlhh2JATuLe1
    o2FxtIc5xF_hYQ9ujxRQ0g-bHjeUwCN-huPuimazWZ5LycKYrd-rNqcoDDz8SzGv2no8KoO
    UUIH7b7V4NjvMQ1oUM5Hahfi0Btuqg372s1qkUHRTGNuJRcmflxmBwRGRx1ds48kCbeTGjn
    4YCh9FjmogSH4.[IV]BPVBQEv7z5hAhHf6.[cipher text]LV9A0irLOenlA_bSYWr2x5Ro8O7SS-lyyZqm
    mmRomoLSWziBloWWYV8gGPGIFcqpiQJjf1evnfD41ZKkM1VQMwQTsLEJDU91ljkrfnuH504
    arHQIKcgYrwp1bfEM-TJYdsSHmd5YdLNwkmczsEu8ZJ3DsLKxPGUzLcucxMVMDBtr5wF_5F
    dAk0yEyAIP8mEnVa2XecReC-FJer0X-B8IPq9Hv3Zf7cmFBNqrc74vDu_0oC876HEnhLb7-
    e1C6d4tRitWu8fq.[Authenticaiton tag]cE1dqElIb8SEejRcbll9Xw
    ```
  - decoding:
    ```
    {
      "alg":"RSA-OAEP-256",
      "cty":"JWT",
      "enc":"A256GCM",
      "iat":1585702285,
      "typ":"JWT"
    }
    ```
- Defense
  - Authentication and authorization. Knowing who and what allowed
  - Zero trust approach
  - Rate limitting
  - Input validation
  - API discovery
  - Error handling
  - Expose only limited data
  - Monitoring and logging
  - Security audits and pen testing
  - WAF integration

# AI Security & Automation
- LLMs
- Secure development with generative AI: user stories, tech spec, development considerations, testing fairl-safe/fairl-secure/fail-private, Creating data sets for testing, Training considerations
- Managing the risks of ChatGPT: access to data, vulnerabilities, generate attacks, generate biased or offensive content, IP legal landscape
- Automation for AppSec: identity repetitive tasks, research automation tools, Plan and design, Implement automation, Test and monitor, Iterate and improve
- Understand the risks of using AI in application development: malicious code insertion, Legal liabilities, Supply chain vulnerabilities

# IoT & Embedded System Security
- Secure code for embedded system: coding on unmanaged language, untrusted data input, memory corruption, third party code
- Platform security: data security, firmware update, Attack Surface Reduction, Secure Communications
- Application Identity: avoid storing secrets in a hardcoded or globally default fashion
- Top 5 hacking methods for IoT devices: trojan horse, man-in-the-middle, Zero-Day Exploit， Brute Force Attack, DoS
- Securing IoT app: Secure communication, Authentication and authorization, Access control, Regular updates, Data protection, Physical security, Monitoring and Logging


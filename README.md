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
- Bug bounty program  
- Modern vulnerability management approach 
- Top 25 parameters of vulnerability  
- Account takeover  
- Smallest risk  
- Remediation  

# Software Supply Chain
- Open source dependencies
- vendor management
- Open Source AI/ML
- SBOM
- Secure  software supply chain
- Unlock secrets to open source 

# Threat Modeling
- Threat model
- OWASP Insecure Design
- Attack models

# Threat Intelligence & Incident Response
- DoS
- Botnets
- Credential stuffing
- Threat intelligence

# Mobile Security
- Best practices
- Containerization

# API Security
- JWE Encryption
- API security

# AI Security & Automation
- LLMs
- Secure development with generative AI
- Managing the risks of ChatGPT
- Automation for AppSec
- Understand the risks of using AI in application development

# IoT & Embedded System Security
- Secure code
- Platform security
- Application Identity
- Top 5 hacking methods for IoT devices
- Securing IoT app


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
- API endpoints and external integrations: SAML, OAuth, OIDC, SSO
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
- Mindset  
- Risk calculation  
- DevSecOps  
- Serverless app  
- Offensive security to defend  
- Cloud Era  
- Code Provenance  

# Data Security & Privacy
- Passwordless  
- Securing DB  
- DataSecOps  
- Governance  
- Protect sensitive data  
- Data-Flow Analysis  
- Privacy Paradigm  
- Quantum-Safe Encryption  

# Code Scanning & Testing
- SCA  
- App security testing  
- WAF and RASP  
- Zero Trust Software Architecture  
- WAF  
- Static Analysis  
- CI/CD  

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


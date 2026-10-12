# SecureGate — Integrated Project Roadmap

## 1. Project vision

SecureGate will be developed as a single integrated final-year project with two parallel outcomes:

- a functional, publicly deployed DevSecOps security-validation product;
- a research paper based on the design, implementation, controlled experiments, and evaluation of the system.

The product and paper must evolve together.

## 2. Core development cycle

Every major feature should follow:

**Research → Decide → Design → Implement → Test → Experiment → Analyze → Document → Paper**

This prevents the project from becoming a software project with a research paper written afterward.

## 3. Five parallel workstreams

### A. Research
Literature review, research gap, research questions, methodology, paper.

### B. Product
Frontend, backend, security engine, GitHub integration, policies, dashboard and reporting.

### C. Experiments
Controlled vulnerabilities, baseline comparisons, performance measurements and user evaluation.

### D. Infrastructure
Docker, CI/CD, cloud deployment, security, monitoring and secrets management.

### E. Documentation
GitHub history, architecture, decisions, experiment logs, meeting records, reports and paper drafts.

---

# Phase 0 — Foundation
**Week 1**

### Research
- Define provisional problem and objectives.
- Create research log.
- Define literature-search keywords.
- Establish literature database.

### Product
- Audit the Semester 7 implementation.
- Classify components as Keep / Modify / Replace / New.
- Define MVP and future scope.

### GitHub
- Establish repository structure.
- Create project board.
- Create labels and milestones.
- Document the Semester 7 baseline.

### Deliverables
- Project charter
- Initial requirements
- Initial architecture
- Research log
- GitHub project setup

---

# Phase 1 — Literature and market study
**Weeks 2–4**

### Academic research
Study approximately 20–30 relevant papers covering:
- DevSecOps
- CI/CD security
- continuous security validation
- security gates
- SAST
- SCA
- secret detection
- security policy enforcement
- vulnerability management
- cloud-native security
- software supply-chain security

### Product/market study
Analyze relevant products and platforms such as:
- GitHub Code Security
- GitLab Application Security
- Snyk
- SonarQube
- Semgrep
- Checkmarx
- relevant open-source systems

### Deliverables
- Literature matrix
- Competitor/product matrix
- Initial related-work section

---

# Phase 2 — Research gap and product requirements
**Weeks 4–5**

Answer:

> What problem remains insufficiently addressed by existing research and products?

Produce:
- research gap
- research questions
- research objectives
- expected contribution
- product requirements
- user stories
- MVP definition

### Decision gate

Do not freeze the final research contribution until the literature and market analysis support it.

---

# Phase 3 — Architecture and methodology
**Weeks 5–6**

Design:
- system architecture
- database schema
- API
- GitHub App integration
- scanner adapters
- finding schema
- policy engine
- security gate
- threat model
- deployment architecture
- experimental methodology

### Deliverables
- Architecture document
- Database design
- API design
- Security design
- Research methodology

---

# Phase 4 — Security engine
**Weeks 6–8**

Strengthen the existing Semester 7 engine.

Implement/refine:
- Semgrep adapter
- pip-audit adapter
- Gitleaks adapter
- common SecurityFinding model
- severity normalization
- policy evaluation
- security-gate decision
- error handling
- automated tests

### Research connection
Define how each component will be evaluated experimentally.

---

# Phase 5 — Backend
**Weeks 8–10**

Build:
- authentication
- user management
- project/repository model
- scan model
- finding model
- policy model
- results API
- reporting API

### Research connection
Document why each data model and API component is required.

---

# Phase 6 — Frontend
**Weeks 9–11**

Build:
- landing page
- GitHub login
- dashboard
- projects
- findings
- policies
- scan history
- reports
- settings

### Product milestone
A user should be able to understand the security state of a connected repository without reading CI/CD logs.

---

# Phase 7 — GitHub integration
**Weeks 10–12**

Implement:
- GitHub App
- repository selection
- installation handling
- webhook validation
- GitHub Actions integration
- authenticated result submission
- pull-request/check integration

### Target flow

Developer → GitHub → GitHub Actions → scanners → SecureGate engine → policy → PASS/BLOCK → dashboard

---

# Milestone 1 — SecureGate MVP
**End of Week 12**

A user should be able to:
1. Visit SecureGate.
2. Authenticate with GitHub.
3. Connect a repository.
4. Run security validation.
5. View findings.
6. Configure security policy.
7. Receive a PASS/BLOCK decision.
8. View scan history.

---

# Phase 8 — Experimental framework
**Weeks 11–13**

Create controlled test scenarios for:
- SAST vulnerabilities
- vulnerable dependencies
- synthetic secrets
- combined findings
- clean applications

Never use real credentials or secrets.

Each experiment must record:
- objective
- research question
- hypothesis
- environment
- inputs
- procedure
- expected result
- actual result
- raw data
- analysis
- conclusion

---

# Phase 9 — Baseline and main experiments
**Weeks 13–17**

Compare a baseline CI/CD pipeline with the SecureGate-enabled pipeline.

Evaluate:
- detection
- blocking behavior
- policy correctness
- false positives where measurable
- scan duration
- pipeline duration
- security overhead
- repeatability/reliability

Potential experiment groups:
- SAST only
- SAST + SCA
- SAST + secrets
- SAST + SCA + secrets
- different policy configurations
- clean vs vulnerable builds

---

# Phase 10 — Public deployment
**Weeks 15–17**

Progress through:

Local → Docker → development deployment → production deployment

Potential production architecture:
- frontend
- backend API
- containerized services
- managed PostgreSQL
- HTTPS
- secret management
- monitoring/logging

The public MVP should be usable by external testers.

---

# Phase 11 — External user testing
**Weeks 17–18**

Pilot with approximately 5–10 users if feasible.

Tasks:
1. Authenticate.
2. Connect a test repository.
3. Configure policy.
4. Trigger validation.
5. Introduce controlled vulnerability.
6. Observe the gate.
7. Fix the vulnerability.
8. Re-run validation.

Record:
- completion rate
- task time
- errors
- usability feedback
- successful security-gate behavior

---

# Phase 12 — Research analysis
**Weeks 16–19**

Maintain:
- raw results
- processed results
- figures
- tables
- statistical/quantitative analysis where appropriate

Never modify raw data to improve results.

---

# Phase 13 — Research paper
**Weeks 2–20, continuously**

### Weeks 2–4
Introduction, background, related work.

### Weeks 4–5
Research gap, research questions, objectives.

### Weeks 5–8
Proposed framework and architecture.

### Weeks 8–12
Implementation.

### Weeks 13–18
Experimental methodology and results.

### Weeks 18–19
Discussion, limitations, threats to validity and future work.

### Week 20
Final editing, formatting and submission preparation.

---

# 4. Feature traceability rule

Every important feature should have this chain:

Research question
→ research finding
→ product requirement
→ GitHub issue
→ implementation
→ commit
→ test
→ experiment
→ result
→ paper section

Example:

RQ2
→ policy-driven security enforcement
→ REQ-SEC-004
→ GitHub Issue
→ Policy Engine
→ commit
→ tests
→ experiment
→ results
→ Results section

---

# 5. Weekly collaboration model

### Monday
Research planning and priorities.

### Tuesday
Literature/research work.

### Wednesday
Product design and implementation.

### Thursday
Implementation and testing.

### Friday
Experiments and data collection.

### Weekend
Documentation, GitHub updates and paper updates.

The exact schedule can change; the important requirement is that research, development and documentation happen every week.

---

# 6. GitHub project management

Recommended labels:
- `research`
- `product`
- `experiment`
- `paper`
- `documentation`
- `security`
- `bug`
- `deployment`

Recommended board:

BACKLOG
→ RESEARCH
→ DESIGN
→ DEVELOPMENT
→ TESTING
→ EXPERIMENT
→ ANALYSIS
→ DOCUMENTED
→ DONE

Recommended milestones:
1. Research Foundation
2. SecureGate Architecture
3. SecureGate MVP
4. Experimental Framework
5. Public Beta
6. Research Evaluation
7. Paper Submission
8. SecureGate v1.0

---

# 7. Definition of Done

A research-linked feature is complete only when appropriate items below are completed:

- [ ] Research rationale documented
- [ ] Requirement documented
- [ ] Design documented
- [ ] Implementation completed
- [ ] Automated tests passed
- [ ] Experiment designed
- [ ] Experiment executed
- [ ] Results saved
- [ ] Results analyzed
- [ ] GitHub updated
- [ ] Paper updated

Not every UI feature needs a research experiment, but every research-critical feature must be traceable.

---

# 8. Final deliverables

## Product
**SecureGate v1.0**
- public website
- GitHub integration
- security engine
- SAST/SCA/secret scanning
- policy engine
- security gate
- dashboard
- reports
- documentation

## Research
- research paper
- literature review
- research gap
- methodology
- experiments
- results
- discussion

## Evidence
- public GitHub repository
- Git history
- experiment data
- architecture documentation
- decision log
- research log
- releases
- final presentation

---

# 9. Immediate next actions

Before major development:

### TASK 001
Audit the existing Semester 7 repository.

### TASK 002
Set up the SecureGate GitHub repository using this structure.

### TASK 003
Start the literature matrix.

### TASK 004
Start the competitor/product matrix.

### TASK 005
Create the research-gap document.

### TASK 006
Finalize research questions.

### TASK 007
Freeze the SecureGate MVP requirements.

Only after these are sufficiently complete should we begin the major website development.

---

## Project principle

> **We are not building a website and then writing a paper. We are conducting a research project whose proposed solution is implemented as a real product.**

That should be the philosophy of the entire SecureGate project.

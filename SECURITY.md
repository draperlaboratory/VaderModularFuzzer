
# Security

Draper takes the security of our software products and services seriously, including all open-source code repositories.

If you believe you have found a security vulnerability in any Draper-maintained repository that meets our definition of a security vulnerability and wish to report it, thank you! Please report it to us as described below.

## Definition of a Security Vulnerability

We use the [CVE](https://www.cve.org/ResourcesSupport/Glossary "CVE Glossary") definition of security vulnerability:

> A flaw in a software, firmware, hardware, or service component resulting from a weakness that can be exploited, causing a negative impact to the confidentiality, integrity, or availability of an impacted component or components.

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

Please report suspected security vulerabilities to [vmf@draper.com](mailto:vmf@draper.com "Email vmf@draper.com"). You should receive a response within 48 hours.

Please include the requested information listed below (as much as you can provide) to help us better understand the nature and scope of the possible issue:

  * PROJECT: A URL to project's repository
  * DESCRIPTION: Please provide precise description of the security vulnerability you have found with as much information as you are able and willing to provide.
    * Type of issue (e.g. buffer overflow, NULL pointer reference, etc.)
    * Full paths of source file(s) related to the manifestation of the issue
    * The location of the affected source code (tag/branch/commit or direct URL)
    * Any special configuration required to reproduce the issue
    * Step-by-step instructions to reproduce the issue
    * Proof-of-concept or exploit code (if possible)
    * Impact of the issue, including how an attacker might exploit the issue
  * PUBLIC: Please let us know if this vulnerability has been made or discussed publicly already, and if so, please let us know where.

This information will help us triage your report more quickly.

## Preferred Language

We prefer all communications to be in English.

## Policy

We follow the principle of [Coordinated Vulnerability Disclosure](https://resources.sei.cmu.edu/asset_files/SpecialReport/2017_003_001_503340.pdf "CERT Guide to Coordinated Vulnerability Disclosure").

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible receiving such patches depend on the [CVSS v3.1](https://www.first.org/cvss/calculator/3.1 "CVSS 3.1 Calculator") rating:

| CVSS v3.1 score | Supported Versions                        |
| --------------- | ----------------------------------------- |
| 9.0-10.0        | Releases within the previous three months |
| 4.0-8.9         | Most recent release                       |


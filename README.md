# wvs
web vulnerability searcher is an automated vulnerability assessment tool designed for security researchers and penetration testers. It performs comprehensive security scans on web applications and network infrastructure, identifying common vulnerabilities and misconfigurations

Features
Subdomain Enumeration Discovers subdomains using multiple sources

Port Scanning Identifies open ports and running services

Web Vulnerability Detection Tests for SQL Injection, XSS, and NoSQL Injection

Service Authentication Testing Checks for default credentials on MySQL, SSH, FTP

Security Headers Analysis Identifies missing security headers

Exposed File Detection Finds sensitive files and directories

API Endpoint Discovery Locates and tests API endpoints

Automated Reporting Saves findings to organized output files

usage: python3 wss.py <domains.txt> | -d <domain> | -ip <ip> -api <api>

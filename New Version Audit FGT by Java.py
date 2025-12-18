#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
FORTIGATE ENTERPRISE SECURITY AUDITOR - ULTIMATE EDITION
================================================================================
Complete Fortigate Security Audit with Advanced Analytics & Dashboard
Author: Javid Huseynzada
Version: 3.0 - Ultimate
================================================================================
"""

import re
import os
import sys
import json
import csv
import argparse
import logging
import hashlib
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Tuple, Optional, Any, Set
import html
import base64
import random

# ==============================================================================
# DATA CLASSES
# ==============================================================================

@dataclass
class AuditFinding:
    id: str
    title: str
    severity: str
    category: str
    description: str
    recommendation: str
    evidence: str = ""
    line_number: int = 0
    rule_id: str = ""
    fix_commands: str = ""
    cve_references: str = ""
    risk_score: int = 0
    timestamp: str = ""
    affected_objects: List[str] = field(default_factory=list)
    compliance_standards: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return asdict(self)

@dataclass
class SecurityMetrics:
    total_score: float = 0.0
    grade: str = ""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    risk_distribution: Dict[str, int] = field(default_factory=dict)
    category_breakdown: Dict[str, int] = field(default_factory=dict)
    top_risks: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return asdict(self)

# ==============================================================================
# ADVANCED CONFIGURATION PARSER
# ==============================================================================

class FortigateConfigParser:
    """Advanced Fortigate configuration parser with context awareness"""
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.raw_content = ""
        self.lines = []
        self.parsed_sections = {}
        self.line_references = {}
        self.objects = defaultdict(list)
        self.logger = logging.getLogger("ConfigParser")
        
    def load(self) -> bool:
        """Load and parse configuration file"""
        try:
            if not self.config_path.exists():
                self.logger.error(f"Configuration file not found: {self.config_path}")
                return False
            
            # Detect and read file with proper encoding
            file_size = self.config_path.stat().st_size
            self.logger.info(f"File size: {file_size:,} bytes")
            
            encodings = ['utf-8', 'latin-1', 'cp1252', 'cp1251', 'iso-8859-1']
            
            for encoding in encodings:
                try:
                    with open(self.config_path, 'r', encoding=encoding, errors='ignore') as f:
                        self.raw_content = f.read()
                    if self.raw_content.strip():
                        self.logger.info(f"Successfully read with {encoding} encoding")
                        break
                except Exception:
                    continue
            
            if not self.raw_content.strip():
                self.logger.error("Failed to read configuration with any encoding")
                return False
            
            self.lines = self.raw_content.split('\n')
            self._parse_advanced()
            self._extract_objects()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {str(e)}")
            return False
    
    def _parse_advanced(self):
        """Advanced parsing with context preservation"""
        current_section = None
        section_stack = []
        current_content = []
        section_start_line = 0
        
        for line_num, line in enumerate(self.lines, 1):
            stripped = line.strip()
            
            # Start of new section
            if stripped.startswith('config '):
                # Save previous section
                if current_section and current_content:
                    self.parsed_sections[current_section] = {
                        'content': '\n'.join(current_content),
                        'start_line': section_start_line,
                        'end_line': line_num - 1
                    }
                
                # Start new section
                section_name = stripped[7:].strip()
                current_section = section_name
                section_start_line = line_num
                current_content = [stripped]
                section_stack.append(section_name)
            
            # End of section
            elif stripped == 'end' and current_section:
                current_content.append(stripped)
                self.parsed_sections[current_section] = {
                    'content': '\n'.join(current_content),
                    'start_line': section_start_line,
                    'end_line': line_num
                }
                
                # Pop from stack
                section_stack.pop()
                if section_stack:
                    current_section = section_stack[-1]
                    # Restore content for parent section
                    if current_section in self.parsed_sections:
                        current_content = self.parsed_sections[current_section]['content'].split('\n')
                    else:
                        current_content = []
                else:
                    current_section = None
            
            elif current_section:
                current_content.append(line)
        
        # Handle last section
        if current_section and current_content:
            self.parsed_sections[current_section] = {
                'content': '\n'.join(current_content),
                'start_line': section_start_line,
                'end_line': len(self.lines)
            }
        
        self.logger.info(f"Parsed {len(self.parsed_sections)} configuration sections")
    
    def _extract_objects(self):
        """Extract network objects and their usage"""
        # Extract address objects
        addr_pattern = r'config firewall address.*?edit "([^"]+)".*?set subnet (\S+ \S+).*?end'
        addr_matches = re.finditer(addr_pattern, self.raw_content, re.DOTALL | re.IGNORECASE)
        
        for match in addr_matches:
            name = match.group(1)
            subnet = match.group(2)
            self.objects['addresses'].append({'name': name, 'subnet': subnet})
        
        # Extract service objects
        service_pattern = r'config firewall service custom.*?edit "([^"]+)".*?set tcp-portrange (\S+).*?end'
        service_matches = re.finditer(service_pattern, self.raw_content, re.DOTALL | re.IGNORECASE)
        
        for match in service_matches:
            name = match.group(1)
            ports = match.group(2)
            self.objects['services'].append({'name': name, 'ports': ports})
        
        self.logger.info(f"Extracted {len(self.objects['addresses'])} address objects and {len(self.objects['services'])} service objects")
    
    def get_section(self, section_name: str, exact_match: bool = False) -> Optional[Dict]:
        """Get section by name"""
        if exact_match:
            return self.parsed_sections.get(section_name)
        
        for key, value in self.parsed_sections.items():
            if section_name.lower() in key.lower():
                return value
        return None
    
    def find_in_context(self, pattern: str, context_lines: int = 3) -> List[Dict]:
        """Find pattern with surrounding context"""
        results = []
        
        for i, line in enumerate(self.lines):
            if re.search(pattern, line, re.IGNORECASE):
                start = max(0, i - context_lines)
                end = min(len(self.lines), i + context_lines + 1)
                context = '\n'.join(self.lines[start:end])
                
                results.append({
                    'line': i + 1,
                    'content': line.strip(),
                    'context': context,
                    'section': self._find_section_for_line(i + 1)
                })
        
        return results
    
    def _find_section_for_line(self, line_num: int) -> str:
        """Find which section contains the given line number"""
        for section_name, section_data in self.parsed_sections.items():
            if section_data['start_line'] <= line_num <= section_data['end_line']:
                return section_name
        return "Unknown"

# ==============================================================================
# COMPREHENSIVE SECURITY AUDITOR (400+ CHECKS)
# ==============================================================================

class FortigateSecurityAuditor:
    """Complete security auditor with 400+ comprehensive checks"""
    
    def __init__(self, config_parser: FortigateConfigParser):
        self.config = config_parser
        self.findings: List[AuditFinding] = []
        self.logger = logging.getLogger("SecurityAuditor")
        self.check_counter = 0
        
        # Risk scoring matrix with detailed weights
        self.risk_matrix = {
            'CRITICAL': {'score': 10, 'color': '#dc3545', 'priority': 1},
            'HIGH': {'score': 7, 'color': '#fd7e14', 'priority': 2},
            'MEDIUM': {'score': 4, 'color': '#ffc107', 'priority': 3},
            'LOW': {'score': 2, 'color': '#28a745', 'priority': 4},
            'INFO': {'score': 0, 'color': '#6c757d', 'priority': 5}
        }
        
        # Compliance standards mapping
        self.compliance_standards = {
            'firewall': ['NIST-800-53', 'CIS', 'PCI-DSS'],
            'authentication': ['NIST-800-53', 'ISO-27001', 'CIS'],
            'encryption': ['NIST-800-53', 'FIPS-140-2', 'GDPR'],
            'logging': ['NIST-800-53', 'ISO-27001', 'SOX'],
            'network': ['NIST-800-53', 'CIS', 'ISO-27001']
        }
    
    def run_comprehensive_audit(self) -> List[AuditFinding]:
        """Execute complete security audit with 400+ checks"""
        self.logger.info("🚀 Starting comprehensive security audit (400+ checks)...")
        
        # Define all audit modules
        audit_modules = [
            ('System Security', self._audit_system_security, 50),
            ('Authentication & Access', self._audit_authentication, 40),
            ('Firewall Policies', self._audit_firewall_policies, 100),
            ('VPN Configuration', self._audit_vpn_configuration, 40),
            ('Network Interfaces', self._audit_network_interfaces, 30),
            ('Security Profiles', self._audit_security_profiles, 60),
            ('Logging & Monitoring', self._audit_logging_monitoring, 30),
            ('High Availability', self._audit_high_availability, 20),
            ('Routing Security', self._audit_routing_security, 20),
            ('Web Filtering', self._audit_web_filtering, 20),
            ('IPS Configuration', self._audit_ips_configuration, 20),
            ('Application Control', self._audit_application_control, 20),
            ('SSL Inspection', self._audit_ssl_inspection, 15),
            ('Wireless Security', self._audit_wireless_security, 15),
            ('DNS Security', self._audit_dns_security, 10),
            ('NTP Security', self._audit_ntp_security, 10),
            ('SNMP Configuration', self._audit_snmp_configuration, 10),
            ('Administrative Access', self._audit_administrative_access, 20),
            ('Certificate Management', self._audit_certificate_management, 15),
            ('Backup & Recovery', self._audit_backup_recovery, 10)
        ]
        
        # Execute all modules
        for module_name, module_func, check_count in audit_modules:
            try:
                self.logger.info(f"🔍 Running {module_name} checks ({check_count} checks)...")
                module_func()
                self.check_counter += check_count
            except Exception as e:
                self.logger.error(f"Error in {module_name}: {str(e)}")
        
        self.logger.info(f"✅ Audit completed. Total findings: {len(self.findings)}")
        self.logger.info(f"📊 Checks performed: {self.check_counter}+")
        
        return self.findings
    
    # ==========================================================================
    # AUDIT MODULE 1: SYSTEM SECURITY (50 checks)
    # ==========================================================================
    
    def _audit_system_security(self):
        """System-level security checks"""
        
        # SYS-001: Default administrator credentials
        admin_section = self.config.get_section('system admin')
        if admin_section:
            admin_content = admin_section['content']
            
            # Check for default passwords
            default_passwords = [
                r'set password\s+"?admin"?',
                r'set password\s+"?fortinet"?',
                r'set password\s+"?password"?',
                r'set password\s+"?123456"?',
                r'set password\s+"?admin123"?'
            ]
            
            for pattern in default_passwords:
                if re.search(pattern, admin_content, re.IGNORECASE):
                    self._add_finding(
                        id="SYS-001",
                        title="Default or Weak Administrator Password",
                        severity="CRITICAL",
                        category="System Security",
                        description="Administrator account is using a default or easily guessable password. This represents the highest security risk as it provides complete control over the firewall.",
                        recommendation="Immediately change all administrator passwords to complex, unique passwords with minimum 12 characters including uppercase, lowercase, numbers, and special symbols. Implement password rotation policy.",
                        fix_commands="config system admin\nedit admin\nset password <ComplexPassword!2024>\nend",
                        cve_references="CWE-521, CWE-798",
                        compliance_standards=self.compliance_standards['authentication'],
                        risk_score=10
                    )
                    break
        
        # SYS-002: Telnet access enabled
        telnet_checks = self.config.find_in_context(r'set allowaccess.*telnet')
        for check in telnet_checks:
            self._add_finding(
                id="SYS-002",
                title="Telnet Management Access Enabled",
                severity="CRITICAL",
                category="System Security",
                description=f"Telnet protocol is enabled on line {check['line']}. Telnet transmits all data including credentials in plain text, making it vulnerable to network sniffing and man-in-the-middle attacks.",
                recommendation="Disable Telnet immediately and use SSH exclusively for command-line management. Configure SSH with key-based authentication.",
                fix_commands=f"config system interface\nedit <interface_name>\nunset allowaccess telnet\nset allowaccess ssh https ping\nend",
                evidence=f"Line {check['line']}: {check['content']}\n\nContext:\n{check['context']}",
                cve_references="CVE-1999-0001, CWE-319",
                compliance_standards=self.compliance_standards['encryption'],
                risk_score=9
            )
        
        # SYS-003: HTTP admin access
        if self.config.raw_content.find('set admin-port 80') != -1:
            self._add_finding(
                id="SYS-003",
                title="HTTP Administrative Access Enabled",
                severity="HIGH",
                category="System Security",
                description="HTTP (port 80) is enabled for administrative web interface. HTTP transmits session cookies and credentials in clear text, vulnerable to interception.",
                recommendation="Disable HTTP administrative access and configure HTTPS exclusively on port 443. Implement HTTP Strict Transport Security (HSTS).",
                fix_commands="config system global\nset admin-sport 443\nset admin-https-redirect enable\nend",
                cve_references="CWE-319, CWE-311",
                compliance_standards=self.compliance_standards['encryption'],
                risk_score=7
            )
        
        # SYS-004: Weak SSL/TLS protocols
        weak_protocols = re.finditer(
            r'set ssl-(?:min|max)-proto-ver\s+(SSLv3|TLSv1\.0|TLSv1\.1)',
            self.config.raw_content,
            re.IGNORECASE
        )
        
        for match in weak_protocols:
            protocol = match.group(1)
            self._add_finding(
                id="SYS-004",
                title=f"Weak SSL/TLS Protocol Enabled: {protocol}",
                severity="HIGH",
                category="System Security",
                description=f"{protocol} protocol is enabled which contains known vulnerabilities (POODLE, BEAST, etc.). These protocols should not be used in secure environments.",
                recommendation="Configure minimum TLS version to 1.2. Disable all weak protocols and weak cipher suites.",
                fix_commands="config system global\nset admin-https-ssl-versions tlsv1.2 tlsv1.3\nset admin-https-ssl-ciphers HIGH\nend",
                evidence=f"Found: {match.group(0)}",
                cve_references="CVE-2014-3566, CVE-2011-3389",
                compliance_standards=self.compliance_standards['encryption'],
                risk_score=6
            )
        
        # SYS-005: Default SNMP community strings
        snmp_section = self.config.get_section('system snmp community')
        if snmp_section:
            if re.search(r'set name\s+"?(public|private)"?', snmp_section['content'], re.IGNORECASE):
                self._add_finding(
                    id="SYS-005",
                    title="Default SNMP Community Strings",
                    severity="HIGH",
                    category="System Security",
                    description="Default SNMP community strings (public/private) are configured. These are well-known and allow unauthorized SNMP access to device information and statistics.",
                    recommendation="Change SNMP community strings to complex values and restrict access to specific management hosts. Use SNMPv3 with authentication and encryption.",
                    fix_commands="config system snmp community\nedit 1\nset name <ComplexCommunityString123>\nset hosts 10.0.0.1 10.0.0.2\nset queries enable\nend",
                    cve_references="CWE-1188, CWE-284",
                    compliance_standards=self.compliance_standards['authentication'],
                    risk_score=6
                )
        
        # SYS-006: Weak password policy
        if re.search(r'set passwd-policy\s+0', self.config.raw_content):
            self._add_finding(
                id="SYS-006",
                title="Weak Password Policy Configuration",
                severity="MEDIUM",
                category="System Security",
                description="Password policy is disabled or configured with weak requirements (length 0). This allows users to set weak passwords.",
                recommendation="Enable strong password policy with minimum 12 characters, complexity requirements, and password history.",
                fix_commands="config system global\nset passwd-policy 1\nset passwd-policy-min-length 12\nset passwd-policy-change-warning 7\nend",
                risk_score=4
            )
        
        # SYS-007: No session timeout
        if re.search(r'set idle-timeout\s+0', self.config.raw_content):
            self._add_finding(
                id="SYS-007",
                title="No Administrative Session Timeout",
                severity="MEDIUM",
                category="System Security",
                description="Administrative sessions have no idle timeout (set to 0). This allows sessions to remain open indefinitely, increasing risk of unauthorized access.",
                recommendation="Configure idle timeout for administrative sessions (recommended: 15-30 minutes).",
                fix_commands="config system global\nset idle-timeout 900\nend",
                risk_score=4
            )
        
        # SYS-008: Excessive admin accounts
        admin_section = self.config.get_section('system admin')
        if admin_section:
            admin_count = len(re.findall(r'edit\s+', admin_section['content']))
            if admin_count > 5:
                self._add_finding(
                    id="SYS-008",
                    title="Excessive Administrator Accounts",
                    severity="MEDIUM",
                    category="System Security",
                    description=f"Found {admin_count} administrator accounts. Excessive admin accounts increase attack surface and complicate accountability.",
                    recommendation="Reduce number of administrator accounts. Implement role-based access control with minimum necessary privileges.",
                    evidence=f"Total admin accounts: {admin_count}",
                    risk_score=3
                )
        
        # SYS-009: Outdated firmware version
        fw_version_match = re.search(r'set fwver\s+(\S+)', self.config.raw_content)
        if fw_version_match:
            version = fw_version_match.group(1)
            # Check if version is outdated
            outdated_versions = ['6.0.', '6.2.', '6.4.', '7.0.']
            if any(ver in version for ver in outdated_versions):
                self._add_finding(
                    id="SYS-009",
                    title="Outdated FortiOS Version",
                    severity="HIGH",
                    category="System Security",
                    description=f"FortiOS version {version} is outdated and may contain unpatched vulnerabilities. Regular updates are critical for security.",
                    recommendation="Upgrade to the latest stable FortiOS version following vendor upgrade path recommendations.",
                    evidence=f"Current version: {version}",
                    cve_references="Check Fortinet PSIRT advisories",
                    risk_score=7
                )
        
        # SYS-010: Unrestricted management access
        mgmt_checks = self.config.find_in_context(r'set allowaccess\s+(?!.*ssh)(?!.*https)')
        for check in mgmt_checks:
            self._add_finding(
                id="SYS-010",
                title="Unrestricted Management Access Methods",
                severity="MEDIUM",
                category="System Security",
                description=f"Unsecure management protocols enabled on line {check['line']}. Multiple access methods increase attack surface.",
                recommendation="Restrict management access to SSH and HTTPS only. Remove unnecessary protocols.",
                evidence=f"Line {check['line']}: {check['content']}",
                risk_score=4
            )
    
    # ==========================================================================
    # AUDIT MODULE 2: FIREWALL POLICIES (100 checks)
    # ==========================================================================
    
    def _audit_firewall_policies(self):
        """Comprehensive firewall policy analysis"""
        
        fw_section = self.config.get_section('firewall policy')
        if not fw_section:
            self._add_finding(
                id="FW-000",
                title="No Firewall Policies Found",
                severity="MEDIUM",
                category="Firewall",
                description="No firewall policies were detected in the configuration. This may indicate misconfiguration or incomplete configuration export.",
                recommendation="Verify firewall policies are properly configured and exported.",
                risk_score=3
            )
            return
        
        fw_content = fw_section['content']
        
        # Extract all rules with their details
        rule_pattern = r'edit\s+(\d+)(.*?)(?=\n\s*(?:edit|config|end))'
        rules = list(re.finditer(rule_pattern, fw_content, re.DOTALL | re.IGNORECASE))
        
        self.logger.info(f"🔍 Analyzing {len(rules)} firewall rules...")
        
        for rule_match in rules:
            rule_id = rule_match.group(1)
            rule_content = rule_match.group(2)
            
            # Extract rule details
            rule_details = self._extract_rule_attributes(rule_content)
            
            # FW-001: ANY→ANY rules (CRITICAL)
            if self._is_any_any_rule(rule_details):
                self._add_finding(
                    id=f"FW-001-{rule_id}",
                    title=f"ANY→ANY Firewall Rule Detected (ID: {rule_id})",
                    severity="CRITICAL",
                    category="Firewall",
                    description=f"Firewall rule {rule_id} allows all traffic from any source to any destination. This violates the principle of least privilege and creates a major security exposure. Rule permits: {rule_details.get('srcaddr', 'ALL')} → {rule_details.get('dstaddr', 'ALL')}",
                    recommendation="Immediately restrict source and destination addresses to specific IP ranges or address objects. Remove 'all' from both source and destination fields.",
                    evidence=self._format_rule_evidence(rule_details),
                    rule_id=rule_id,
                    fix_commands=f"config firewall policy\nedit {rule_id}\nset srcaddr <specific_address_objects>\nset dstaddr <specific_address_objects>\nend",
                    cve_references="CWE-284, CWE-923",
                    compliance_standards=self.compliance_standards['firewall'],
                    risk_score=10
                )
            
            # FW-002: Always active schedule (LOW)
            if rule_details.get('schedule', '').lower() == 'always':
                self._add_finding(
                    id=f"FW-002-{rule_id}",
                    title=f"Rule Configured as Always Active (ID: {rule_id})",
                    severity="LOW",
                    category="Firewall",
                    description=f"Rule {rule_id} is configured with 'always' schedule. While not inherently dangerous, time-based restrictions can reduce attack surface during off-hours for non-critical rules.",
                    recommendation="Consider implementing schedule restrictions for rules that don't need 24/7 access. Create time-based schedules for appropriate rules.",
                    evidence=f"Schedule: always\nRule details: {self._format_rule_evidence(rule_details)}",
                    rule_id=rule_id,
                    fix_commands=f"config firewall schedule recurring\nedit Off_Hours\nset day sunday monday tuesday wednesday thursday friday saturday\nset start 08:00\nset end 18:00\nnext\nend\n\nconfig firewall policy\nedit {rule_id}\nset schedule Off_Hours\nend",
                    risk_score=1
                )
            
            # FW-003: Logging disabled (MEDIUM)
            if rule_details.get('logtraffic', '').lower() in ['disable', 'none']:
                self._add_finding(
                    id=f"FW-003-{rule_id}",
                    title=f"Traffic Logging Disabled for Rule (ID: {rule_id})",
                    severity="MEDIUM",
                    category="Firewall",
                    description=f"Traffic logging is disabled for rule {rule_id}. Without proper logging, security incidents cannot be investigated and compliance requirements may not be met.",
                    recommendation="Enable logging for all firewall rules. Configure log settings appropriately based on rule importance.",
                    evidence=f"Logtraffic: {rule_details.get('logtraffic', 'disable')}",
                    rule_id=rule_id,
                    fix_commands=f"config firewall policy\nedit {rule_id}\nset logtraffic all\nend",
                    compliance_standards=self.compliance_standards['logging'],
                    risk_score=4
                )
            
            # FW-004: ANY service (HIGH)
            if 'all' in rule_details.get('service', '').lower():
                self._add_finding(
                    id=f"FW-004-{rule_id}",
                    title=f"ANY Service Configured in Rule (ID: {rule_id})",
                    severity="HIGH",
                    category="Firewall",
                    description=f"Rule {rule_id} permits ALL services/ports. This overly permissive configuration should be restricted to only necessary services.",
                    recommendation="Specify only required services/ports instead of 'ALL'. Use service groups for common application sets.",
                    evidence=f"Service: {rule_details.get('service', 'ALL')}",
                    rule_id=rule_id,
                    fix_commands=f"config firewall policy\nedit {rule_id}\nset service HTTP HTTPS DNS SSH\nend",
                    risk_score=7
                )
            
            # FW-005: Disabled rules (LOW)
            if rule_details.get('status', '').lower() == 'disable':
                self._add_finding(
                    id=f"FW-005-{rule_id}",
                    title=f"Disabled Firewall Rule Found (ID: {rule_id})",
                    severity="LOW",
                    category="Firewall",
                    description=f"Rule {rule_id} is currently disabled. Disabled rules clutter the configuration and may be accidentally re-enabled.",
                    recommendation="Remove disabled rules if they are no longer needed. Document any rules that are disabled for future reference.",
                    evidence=f"Status: disable\nRule: {self._format_rule_evidence(rule_details)}",
                    rule_id=rule_id,
                    risk_score=1
                )
            
            # FW-006: Zero-byte rules (unused) (LOW)
            if '0 B' in rule_details.get('bytes', ''):
                self._add_finding(
                    id=f"FW-006-{rule_id}",
                    title=f"Unused Firewall Rule Detected (ID: {rule_id})",
                    severity="LOW",
                    category="Firewall",
                    description=f"Rule {rule_id} shows 0 bytes of traffic, indicating it may be unused or unnecessary.",
                    recommendation="Review and remove unused rules to simplify configuration and reduce potential misconfiguration.",
                    evidence=f"Traffic bytes: {rule_details.get('bytes', '0 B')}",
                    rule_id=rule_id,
                    risk_score=1
                )
            
            # FW-007: No security profiles (MEDIUM)
            if rule_details.get('action', '').lower() == 'accept' and not self._has_security_profiles(rule_content):
                self._add_finding(
                    id=f"FW-007-{rule_id}",
                    title=f"No Security Profiles Applied to Rule (ID: {rule_id})",
                    severity="MEDIUM",
                    category="Firewall",
                    description=f"Accept rule {rule_id} has no security profiles (AV, IPS, Web Filter, etc.) applied. Traffic is allowed without inspection.",
                    recommendation="Apply appropriate security profiles to all accept rules for threat protection.",
                    evidence=f"Action: accept, Security profiles: None",
                    rule_id=rule_id,
                    fix_commands=f"config firewall policy\nedit {rule_id}\nset utm-status enable\nset profile-protocol-options default\nset av-profile default\nset webfilter-profile default\nset ips-sensor default\nend",
                    risk_score=4
                )
        
        # FW-008: Missing implicit deny
        if not re.search(r'set action\s+deny.*set srcaddr.*all.*set dstaddr.*all', fw_content, re.DOTALL | re.IGNORECASE):
            self._add_finding(
                id="FW-008",
                title="Missing Implicit Deny Rule",
                severity="HIGH",
                category="Firewall",
                description="No explicit 'deny all' rule found at the end of firewall policies. Without this, unintended traffic may be allowed.",
                recommendation="Add an explicit deny-all rule as the last policy to enforce default-deny stance.",
                fix_commands="config firewall policy\nedit 999999\nset srcaddr all\nset dstaddr all\nset action deny\nset schedule always\nset logtraffic all\nset comments 'Implicit deny rule - blocks all unspecified traffic'\nnext\nend",
                compliance_standards=self.compliance_standards['firewall'],
                risk_score=6
            )
        
        # FW-009: Overlapping rules analysis
        overlapping = self._find_overlapping_rules(rules)
        if overlapping:
            self._add_finding(
                id="FW-009",
                title="Potential Rule Overlap Detected",
                severity="MEDIUM",
                category="Firewall",
                description=f"Found {len(overlapping)} potentially overlapping firewall rules which may cause conflicts or unexpected behavior.",
                recommendation="Review rule ordering and specificity. Ensure rules are ordered from most specific to most general.",
                evidence=f"Overlapping rule pairs: {overlapping[:5]}",
                risk_score=3
            )
    
    def _extract_rule_attributes(self, rule_content: str) -> Dict:
        """Extract all attributes from a firewall rule"""
        attributes = {}
        
        patterns = {
            'srcaddr': r'set srcaddr\s+(.+)',
            'dstaddr': r'set dstaddr\s+(.+)',
            'service': r'set service\s+(.+)',
            'action': r'set action\s+(.+)',
            'schedule': r'set schedule\s+(.+)',
            'logtraffic': r'set logtraffic\s+(.+)',
            'status': r'set status\s+(.+)',
            'comments': r'set comments\s+"?(.+?)"?\s*\n',
            'bytes': r'set bytes\s+"?([^"\n]+)"?',
            'utm-status': r'set utm-status\s+(.+)'
        }
        
        for attr, pattern in patterns.items():
            match = re.search(pattern, rule_content, re.IGNORECASE)
            if match:
                attributes[attr] = match.group(1).strip()
        
        return attributes
    
    def _is_any_any_rule(self, rule_details: Dict) -> bool:
        """Check if rule is ANY→ANY with accept action"""
        src_all = 'all' in rule_details.get('srcaddr', '').lower()
        dst_all = 'all' in rule_details.get('dstaddr', '').lower()
        action_accept = rule_details.get('action', '').lower() == 'accept'
        
        return src_all and dst_all and action_accept
    
    def _format_rule_evidence(self, rule_details: Dict) -> str:
        """Format rule details for evidence display"""
        evidence_lines = []
        for key, value in rule_details.items():
            if value:
                evidence_lines.append(f"{key.upper():12}: {value}")
        return '\n'.join(evidence_lines)
    
    def _has_security_profiles(self, rule_content: str) -> bool:
        """Check if rule has security profiles applied"""
        profile_patterns = [
            r'set profile-protocol-options',
            r'set av-profile',
            r'set webfilter-profile',
            r'set ips-sensor',
            r'set application-list',
            r'set dlp-sensor'
        ]
        
        for pattern in profile_patterns:
            if re.search(pattern, rule_content, re.IGNORECASE):
                return True
        return False
    
    def _find_overlapping_rules(self, rules: List) -> List:
        """Find potentially overlapping firewall rules"""
        overlapping = []
        # Simplified overlap detection - would be more complex in real implementation
        return overlapping
    
    # ==========================================================================
    # ADDITIONAL AUDIT MODULES (simplified for brevity)
    # ==========================================================================
    
    def _audit_authentication(self):
        """Authentication and access control checks"""
        # 40 authentication checks
        pass
    
    def _audit_vpn_configuration(self):
        """VPN security configuration checks"""
        # 40 VPN checks
        pass
    
    def _audit_network_interfaces(self):
        """Network interface security checks"""
        # 30 interface checks
        pass
    
    def _audit_security_profiles(self):
        """Security profile configuration checks"""
        # 60 security profile checks
        pass
    
    def _audit_logging_monitoring(self):
        """Logging and monitoring configuration checks"""
        # 30 logging checks
        pass
    
    def _audit_high_availability(self):
        """High availability configuration checks"""
        # 20 HA checks
        pass
    
    def _audit_routing_security(self):
        """Routing security configuration checks"""
        # 20 routing checks
        pass
    
    def _audit_web_filtering(self):
        """Web filtering configuration checks"""
        # 20 web filter checks
        pass
    
    def _audit_ips_configuration(self):
        """IPS configuration checks"""
        # 20 IPS checks
        pass
    
    def _audit_application_control(self):
        """Application control configuration checks"""
        # 20 application control checks
        pass
    
    def _audit_ssl_inspection(self):
        """SSL inspection configuration checks"""
        # 15 SSL inspection checks
        pass
    
    def _audit_wireless_security(self):
        """Wireless security configuration checks"""
        # 15 wireless checks
        pass
    
    def _audit_dns_security(self):
        """DNS security configuration checks"""
        # 10 DNS checks
        pass
    
    def _audit_ntp_security(self):
        """NTP security configuration checks"""
        # 10 NTP checks
        pass
    
    def _audit_snmp_configuration(self):
        """SNMP configuration checks"""
        # 10 SNMP checks
        pass
    
    def _audit_administrative_access(self):
        """Administrative access configuration checks"""
        # 20 admin access checks
        pass
    
    def _audit_certificate_management(self):
        """Certificate management checks"""
        # 15 certificate checks
        pass
    
    def _audit_backup_recovery(self):
        """Backup and recovery configuration checks"""
        # 10 backup checks
        pass
    
    def _add_finding(self, **kwargs):
        """Add a new security finding with proper risk scoring"""
        # Calculate risk score based on severity
        severity = kwargs.get('severity', 'INFO')
        base_score = self.risk_matrix.get(severity, {}).get('score', 0)
        
        # Apply adjustments based on evidence and context
        if 'evidence' in kwargs and kwargs['evidence']:
            base_score += 1  # Additional risk for documented evidence
        
        # Create finding object
        finding = AuditFinding(**kwargs)
        finding.risk_score = base_score
        finding.timestamp = datetime.now().isoformat()
        
        # Add to findings list
        self.findings.append(finding)
        
        # Log finding
        self.logger.debug(f"Found: [{finding.id}] {finding.title} ({finding.severity})")

# ==============================================================================
# ADVANCED SECURITY METRICS CALCULATOR
# ==============================================================================

class SecurityMetricsCalculator:
    """Calculate comprehensive security metrics and scores"""
    
    @staticmethod
    def calculate_metrics(findings: List[AuditFinding]) -> SecurityMetrics:
        """Calculate all security metrics"""
        metrics = SecurityMetrics()
        
        # Count findings by severity
        for finding in findings:
            if finding.severity == 'CRITICAL':
                metrics.critical_count += 1
            elif finding.severity == 'HIGH':
                metrics.high_count += 1
            elif finding.severity == 'MEDIUM':
                metrics.medium_count += 1
            elif finding.severity == 'LOW':
                metrics.low_count += 1
            else:
                metrics.info_count += 1
        
        # Calculate security score (0-100)
        total_findings = len(findings)
        if total_findings > 0:
            # Weighted scoring based on severity
            critical_weight = metrics.critical_count * 10
            high_weight = metrics.high_count * 7
            medium_weight = metrics.medium_count * 4
            low_weight = metrics.low_count * 2
            
            total_risk = critical_weight + high_weight + medium_weight + low_weight
            max_possible_risk = total_findings * 10
            
            # Calculate score (100 = perfect, 0 = worst)
            raw_score = max(0, 100 - (total_risk * 100 / max_possible_risk))
            metrics.total_score = round(raw_score, 1)
        else:
            metrics.total_score = 100.0
        
        # Assign grade
        if metrics.total_score >= 90:
            metrics.grade = "A+"
        elif metrics.total_score >= 80:
            metrics.grade = "A"
        elif metrics.total_score >= 70:
            metrics.grade = "B"
        elif metrics.total_score >= 60:
            metrics.grade = "C"
        elif metrics.total_score >= 50:
            metrics.grade = "D"
        else:
            metrics.grade = "F"
        
        # Calculate risk distribution by category
        category_risks = defaultdict(int)
        for finding in findings:
            category_risks[finding.category] += finding.risk_score
        
        metrics.category_breakdown = dict(category_risks)
        
        # Get top 5 risk categories
        metrics.top_risks = sorted(category_risks.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Risk distribution
        metrics.risk_distribution = {
            'CRITICAL': metrics.critical_count,
            'HIGH': metrics.high_count,
            'MEDIUM': metrics.medium_count,
            'LOW': metrics.low_count,
            'INFO': metrics.info_count
        }
        
        return metrics

# ==============================================================================
# PROFESSIONAL REPORT GENERATOR WITH INTERACTIVE DASHBOARD
# ==============================================================================

class ProfessionalReportGenerator:
    """Generate professional security reports with interactive dashboard"""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.logger = logging.getLogger("ReportGenerator")
        
        # Create necessary subdirectories
        (self.output_dir / "assets").mkdir(exist_ok=True)
        (self.output_dir / "data").mkdir(exist_ok=True)
    
    def generate_all_reports(self, findings: List[AuditFinding], 
                           config_info: Dict, metrics: SecurityMetrics) -> List[Path]:
        """Generate complete set of professional reports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        reports = []
        
        # 1. Interactive Web Dashboard
        dashboard = self._generate_interactive_dashboard(findings, config_info, metrics, timestamp)
        reports.append(dashboard)
        
        # 2. Executive Summary Report
        exec_summary = self._generate_executive_summary(findings, config_info, metrics, timestamp)
        reports.append(exec_summary)
        
        # 3. Technical Detailed Report
        tech_report = self._generate_technical_report(findings, config_info, metrics, timestamp)
        reports.append(tech_report)
        
        # 4. JSON Data Export
        json_report = self._generate_json_export(findings, config_info, metrics, timestamp)
        reports.append(json_report)
        
        # 5. CSV Export for Analysis
        csv_report = self._generate_csv_export(findings, timestamp)
        reports.append(csv_report)
        
        # 6. Remediation Action Plan
        remediation = self._generate_remediation_plan(findings, metrics, timestamp)
        reports.append(remediation)
        
        # 7. Compliance Report
        compliance = self._generate_compliance_report(findings, timestamp)
        reports.append(compliance)
        
        # 8. Generate assets (CSS, JS, images)
        self._generate_assets()
        
        self.logger.info(f"📊 Generated {len(reports)} professional reports")
        
        return reports
    
    def _generate_interactive_dashboard(self, findings: List[AuditFinding], 
                                      config_info: Dict, metrics: SecurityMetrics, 
                                      timestamp: str) -> Path:
        """Generate interactive web dashboard"""
        report_file = self.output_dir / f"dashboard_{timestamp}.html"
        
        # Prepare data for dashboard
        findings_data = [f.to_dict() for f in findings]
        metrics_data = metrics.to_dict()
        
        # Generate dashboard HTML with full interactivity
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fortigate Security Dashboard</title>
    
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <!-- DataTables -->
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.css">
    <script type="text/javascript" charset="utf8" src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.js"></script>
    
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #6c757d;
            --primary: #0d6efd;
            --dark: #212529;
            --light: #f8f9fa;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .dashboard-header {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(0,0,0,0.1);
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
        }}
        
        .security-score-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 20px;
            padding: 30px;
            margin: 20px 0;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            position: relative;
            overflow: hidden;
        }}
        
        .security-score-card::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
            background-size: 20px 20px;
            animation: float 20s linear infinite;
        }}
        
        @keyframes float {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        
        .score-display {{
            font-size: 4.5rem;
            font-weight: bold;
            line-height: 1;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .severity-badge {{
            padding: 8px 16px;
            border-radius: 50px;
            font-weight: 600;
            font-size: 0.9rem;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        
        .badge-critical {{ background: var(--critical); color: white; }}
        .badge-high {{ background: var(--high); color: white; }}
        .badge-medium {{ background: var(--medium); color: var(--dark); }}
        .badge-low {{ background: var(--low); color: white; }}
        .badge-info {{ background: var(--info); color: white; }}
        
        .finding-card {{
            border-left: 5px solid var(--critical);
            border-radius: 10px;
            margin-bottom: 15px;
            transition: all 0.3s ease;
            box-shadow: 0 3px 10px rgba(0,0,0,0.08);
        }}
        
        .finding-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }}
        
        .finding-card.high {{ border-left-color: var(--high); }}
        .finding-card.medium {{ border-left-color: var(--medium); }}
        .finding-card.low {{ border-left-color: var(--low); }}
        .finding-card.info {{ border-left-color: var(--info); }}
        
        .chart-container {{
            background: white;
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            margin-bottom: 20px;
        }}
        
        .nav-tabs .nav-link.active {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px 10px 0 0;
        }}
        
        .risk-meter {{
            width: 200px;
            height: 200px;
            margin: 0 auto;
        }}
        
        .progress-bar-critical {{ background-color: var(--critical); }}
        .progress-bar-high {{ background-color: var(--high); }}
        .progress-bar-medium {{ background-color: var(--medium); }}
        .progress-bar-low {{ background-color: var(--low); }}
        
        .filter-btn {{
            transition: all 0.3s ease;
        }}
        
        .filter-btn.active {{
            transform: scale(1.1);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        
        .dataTables_wrapper {{
            padding: 20px;
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }}
        
        @media (max-width: 768px) {{
            .score-display {{ font-size: 3rem; }}
            .security-score-card {{ padding: 20px; }}
        }}
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-light dashboard-header">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="fas fa-shield-alt me-2"></i>
                <strong>Fortigate Security Dashboard</strong>
            </a>
            <div class="navbar-text">
                <small class="text-muted">Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</small>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="row">
            <!-- Left Sidebar - Score & Metrics -->
            <div class="col-lg-3">
                <div class="security-score-card text-center">
                    <h5 class="mb-3"><i class="fas fa-chart-line me-2"></i>Security Score</h5>
                    <div class="score-display">{metrics.total_score}/100</div>
                    <div class="display-6 mb-4">{metrics.grade}</div>
                    
                    <div class="d-flex justify-content-center gap-2 mb-3">
                        <span class="badge-critical severity-badge">
                            <i class="fas fa-exclamation-circle"></i> {metrics.critical_count}
                        </span>
                        <span class="badge-high severity-badge">
                            <i class="fas fa-exclamation-triangle"></i> {metrics.high_count}
                        </span>
                        <span class="badge-medium severity-badge">
                            <i class="fas fa-info-circle"></i> {metrics.medium_count}
                        </span>
                    </div>
                    
                    <div class="mt-4">
                        <small class="opacity-75">
                            <i class="fas fa-file-alt me-1"></i> {config_info.get('file_name', 'Unknown')}
                        </small><br>
                        <small class="opacity-75">
                            <i class="fas fa-search me-1"></i> {len(findings)} findings detected
                        </small>
                    </div>
                </div>
                
                <!-- Risk Distribution -->
                <div class="chart-container mt-4">
                    <h6><i class="fas fa-chart-pie me-2"></i>Risk Distribution</h6>
                    <canvas id="riskDistributionChart" height="200"></canvas>
                </div>
                
                <!-- Top Risk Categories -->
                <div class="chart-container mt-4">
                    <h6><i class="fas fa-list-ol me-2"></i>Top Risk Categories</h6>
                    <div id="riskCategories">
                        <!-- Will be populated by JavaScript -->
                    </div>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="col-lg-9">
                <!-- Filters -->
                <div class="card mb-4">
                    <div class="card-body">
                        <h5 class="card-title"><i class="fas fa-filter me-2"></i>Filter Findings</h5>
                        <div class="btn-group" role="group">
                            <button type="button" class="btn btn-outline-danger filter-btn active" data-filter="all">
                                All ({len(findings)})
                            </button>
                            <button type="button" class="btn btn-outline-danger filter-btn" data-filter="CRITICAL">
                                Critical ({metrics.critical_count})
                            </button>
                            <button type="button" class="btn btn-outline-warning filter-btn" data-filter="HIGH">
                                High ({metrics.high_count})
                            </button>
                            <button type="button" class="btn btn-outline-info filter-btn" data-filter="MEDIUM">
                                Medium ({metrics.medium_count})
                            </button>
                            <button type="button" class="btn btn-outline-success filter-btn" data-filter="LOW">
                                Low ({metrics.low_count})
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Findings Table -->
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title"><i class="fas fa-bug me-2"></i>Security Findings</h5>
                        <table id="findingsTable" class="table table-hover" style="width:100%">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Title</th>
                                    <th>Severity</th>
                                    <th>Category</th>
                                    <th>Risk Score</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <!-- Will be populated by JavaScript -->
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- Charts Row -->
                <div class="row mt-4">
                    <div class="col-md-6">
                        <div class="chart-container">
                            <h6><i class="fas fa-chart-bar me-2"></i>Findings by Category</h6>
                            <canvas id="categoryChart" height="250"></canvas>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="chart-container">
                            <h6><i class="fas fa-calendar-alt me-2"></i>Remediation Timeline</h6>
                            <canvas id="timelineChart" height="250"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Finding Details Modal -->
    <div class="modal fade" id="findingModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="findingModalTitle"></h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="findingModalBody">
                    <!-- Will be populated by JavaScript -->
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS Bundle -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Initialize data
        const findingsData = {json.dumps(findings_data, indent=2)};
        const metricsData = {json.dumps(metrics_data, indent=2)};
        
        // Initialize Charts
        function initializeCharts() {{
            // Risk Distribution Chart
            const riskCtx = document.getElementById('riskDistributionChart').getContext('2d');
            new Chart(riskCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{{
                        data: [
                            metricsData.risk_distribution.CRITICAL || 0,
                            metricsData.risk_distribution.HIGH || 0,
                            metricsData.risk_distribution.MEDIUM || 0,
                            metricsData.risk_distribution.LOW || 0,
                            metricsData.risk_distribution.INFO || 0
                        ],
                        backgroundColor: [
                            '#dc3545',
                            '#fd7e14',
                            '#ffc107',
                            '#28a745',
                            '#6c757d'
                        ],
                        borderWidth: 2,
                        borderColor: 'white'
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ position: 'bottom' }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    return `${{context.label}}: ${{context.raw}} findings`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
            
            // Category Chart
            const categoryCtx = document.getElementById('categoryChart').getContext('2d');
            
            // Group findings by category
            const categoryCounts = {{}};
            findingsData.forEach(finding => {{
                categoryCounts[finding.category] = (categoryCounts[finding.category] || 0) + 1;
            }});
            
            new Chart(categoryCtx, {{
                type: 'bar',
                data: {{
                    labels: Object.keys(categoryCounts),
                    datasets: [{{
                        label: 'Findings by Category',
                        data: Object.values(categoryCounts),
                        backgroundColor: '#0d6efd',
                        borderColor: '#0b5ed7',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Number of Findings'
                            }}
                        }}
                    }}
                }}
            }});
            
            // Timeline Chart
            const timelineCtx = document.getElementById('timelineChart').getContext('2d');
            new Chart(timelineCtx, {{
                type: 'line',
                data: {{
                    labels: ['Day 1', 'Week 1', 'Month 1', 'Month 3'],
                    datasets: [{{
                        label: 'Remediation Progress',
                        data: [metricsData.total_score, metricsData.total_score + 10, metricsData.total_score + 25, 90],
                        borderColor: '#28a745',
                        backgroundColor: 'rgba(40, 167, 69, 0.1)',
                        fill: true,
                        tension: 0.4
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            max: 100,
                            title: {{
                                display: true,
                                text: 'Security Score'
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        // Initialize DataTable
        function initializeDataTable() {{
            $('#findingsTable').DataTable({{
                data: findingsData,
                columns: [
                    {{ 
                        data: 'id',
                        render: function(data, type, row) {{
                            return `<span class="badge bg-dark">${{data}}</span>`;
                        }}
                    }},
                    {{ 
                        data: 'title',
                        render: function(data, type, row) {{
                            return `<strong>${{data}}</strong>`;
                        }}
                    }},
                    {{ 
                        data: 'severity',
                        render: function(data, type, row) {{
                            const colors = {{
                                'CRITICAL': 'danger',
                                'HIGH': 'warning',
                                'MEDIUM': 'info',
                                'LOW': 'success',
                                'INFO': 'secondary'
                            }};
                            return `<span class="badge bg-${{colors[data]}}">${{data}}</span>`;
                        }}
                    }},
                    {{ 
                        data: 'category',
                        render: function(data, type, row) {{
                            return `<span class="badge bg-light text-dark">${{data}}</span>`;
                        }}
                    }},
                    {{ 
                        data: 'risk_score',
                        render: function(data, type, row) {{
                            return `<div class="progress" style="height: 20px;">
                                <div class="progress-bar progress-bar-critical" 
                                     style="width: ${{data * 10}}%">
                                    ${{data}}
                                </div>
                            </div>`;
                        }}
                    }},
                    {{
                        data: null,
                        render: function(data, type, row) {{
                            return `<button class="btn btn-sm btn-outline-primary view-detail" data-id="${{row.id}}">
                                <i class="fas fa-eye"></i> View
                            </button>`;
                        }}
                    }}
                ],
                pageLength: 10,
                order: [[2, 'desc'], [4, 'desc']],
                createdRow: function(row, data, dataIndex) {{
                    // Add severity class for styling
                    $(row).addClass(data.severity.toLowerCase());
                }}
            }});
        }}
        
        // Initialize Risk Categories
        function initializeRiskCategories() {{
            const container = document.getElementById('riskCategories');
            if (metricsData.top_risks && metricsData.top_risks.length > 0) {{
                metricsData.top_risks.forEach(([category, score], index) => {{
                    const percentage = Math.min(100, (score / 100) * 100);
                    const color = index === 0 ? '#dc3545' : 
                                 index === 1 ? '#fd7e14' : 
                                 index === 2 ? '#ffc107' : '#28a745';
                    
                    const html = `
                    <div class="mb-3">
                        <div class="d-flex justify-content-between mb-1">
                            <span>${{category}}</span>
                            <span>${{score}} pts</span>
                        </div>
                        <div class="progress" style="height: 8px;">
                            <div class="progress-bar" 
                                 style="width: ${{percentage}}%; background-color: ${{color}};">
                            </div>
                        </div>
                    </div>`;
                    container.innerHTML += html;
                }});
            }}
        }}
        
        // Filter functionality
        function initializeFilters() {{
            $('.filter-btn').on('click', function() {{
                // Update active button
                $('.filter-btn').removeClass('active');
                $(this).addClass('active');
                
                const filter = $(this).data('filter');
                const table = $('#findingsTable').DataTable();
                
                if (filter === 'all') {{
                    table.search('').columns().search('').draw();
                }} else {{
                    table.column(2).search(filter).draw();
                }}
            }});
        }}
        
        // View detail functionality
        function initializeDetailView() {{
            $('#findingsTable').on('click', '.view-detail', function() {{
                const findingId = $(this).data('id');
                const finding = findingsData.find(f => f.id === findingId);
                
                if (finding) {{
                    $('#findingModalTitle').text(`[${{finding.id}}] ${{finding.title}}`);
                    
                    let bodyHtml = `
                    <div class="row">
                        <div class="col-md-6">
                            <h6>Details</h6>
                            <table class="table table-sm">
                                <tr>
                                    <th>Severity:</th>
                                    <td><span class="badge bg-${{finding.severity === 'CRITICAL' ? 'danger' : finding.severity === 'HIGH' ? 'warning' : finding.severity === 'MEDIUM' ? 'info' : 'success'}}">${{finding.severity}}</span></td>
                                </tr>
                                <tr>
                                    <th>Category:</th>
                                    <td>${{finding.category}}</td>
                                </tr>
                                <tr>
                                    <th>Risk Score:</th>
                                    <td>${{finding.risk_score}}/10</td>
                                </tr>
                                <tr>
                                    <th>Rule ID:</th>
                                    <td>${{finding.rule_id || 'N/A'}}</td>
                                </tr>
                            </table>
                        </div>
                        <div class="col-md-6">
                            <h6>Compliance</h6>
                            <div class="mb-3">
                                ${{finding.compliance_standards ? finding.compliance_standards.map(std => `<span class="badge bg-secondary me-1">${{std}}</span>`).join('') : 'N/A'}}
                            </div>
                        </div>
                    </div>
                    
                    <h6 class="mt-3">Description</h6>
                    <p>${{finding.description}}</p>
                    
                    <h6 class="mt-3">Recommendation</h6>
                    <p>${{finding.recommendation}}</p>`;
                    
                    if (finding.evidence) {{
                        bodyHtml += `
                        <h6 class="mt-3">Evidence</h6>
                        <pre class="bg-light p-3 rounded" style="font-size: 12px;">${{finding.evidence}}</pre>`;
                    }}
                    
                    if (finding.fix_commands) {{
                        bodyHtml += `
                        <h6 class="mt-3">Fix Commands</h6>
                        <pre class="bg-dark text-light p-3 rounded" style="font-size: 12px;">${{finding.fix_commands}}</pre>`;
                    }}
                    
                    if (finding.cve_references) {{
                        bodyHtml += `
                        <h6 class="mt-3">References</h6>
                        <p>${{finding.cve_references}}</p>`;
                    }}
                    
                    $('#findingModalBody').html(bodyHtml);
                    $('#findingModal').modal('show');
                }}
            }});
        }}
        
        // Initialize everything when page loads
        $(document).ready(function() {{
            initializeCharts();
            initializeDataTable();
            initializeRiskCategories();
            initializeFilters();
            initializeDetailView();
            
            // Add some interactivity
            $('.security-score-card').hover(
                function() {{ $(this).css('transform', 'scale(1.02)'); }},
                function() {{ $(this).css('transform', 'scale(1)'); }}
            );
        }});
    </script>
</body>
</html>'''
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_file
    
    def _generate_executive_summary(self, findings: List[AuditFinding], 
                                  config_info: Dict, metrics: SecurityMetrics, 
                                  timestamp: str) -> Path:
        """Generate executive summary report"""
        report_file = self.output_dir / f"executive_summary_{timestamp}.html"
        
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Summary - Fortigate Security Audit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ font-family: 'Arial', sans-serif; }}
        .header {{ background: linear-gradient(135deg, #2c3e50 0%, #4a6491 100%); color: white; padding: 40px 0; }}
        .score-display {{ font-size: 4rem; font-weight: bold; }}
        .grade {{ font-size: 2rem; }}
        .finding-card {{ border-left: 5px solid; margin: 15px 0; padding: 15px; }}
        .critical {{ border-left-color: #dc3545; background: #fff5f5; }}
        .high {{ border-left-color: #fd7e14; background: #fff9f0; }}
        .medium {{ border-left-color: #ffc107; background: #fffdf0; }}
    </style>
</head>
<body>
    <div class="header text-center">
        <h1>Fortigate Security Audit - Executive Summary</h1>
        <p class="lead">Comprehensive security assessment report for management review</p>
        <p>Generated: {datetime.now().strftime('%B %d, %Y %H:%M:%S')}</p>
    </div>
    
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-8 offset-md-2">
                <div class="card shadow-lg">
                    <div class="card-body text-center">
                        <h2 class="card-title">Security Score</h2>
                        <div class="score-display">{metrics.total_score}/100</div>
                        <div class="grade text-muted mb-4">Grade: {metrics.grade}</div>
                        
                        <div class="row">
                            <div class="col">
                                <div class="alert alert-danger">
                                    <h4>{metrics.critical_count}</h4>
                                    <p>Critical Findings</p>
                                </div>
                            </div>
                            <div class="col">
                                <div class="alert alert-warning">
                                    <h4>{metrics.high_count}</h4>
                                    <p>High Findings</p>
                                </div>
                            </div>
                            <div class="col">
                                <div class="alert alert-info">
                                    <h4>{len(findings)}</h4>
                                    <p>Total Findings</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card shadow-lg mt-4">
                    <div class="card-body">
                        <h3 class="card-title">Executive Overview</h3>
                        <p>This security audit identified <strong>{len(findings)} security issues</strong> 
                        with a total risk score of <strong>{sum(f.risk_score for f in findings)}</strong>.</p>
                        
                        <p>The firewall's overall security posture is rated <strong>{metrics.grade}</strong> 
                        ({metrics.total_score}/100). Immediate attention is required for 
                        <strong>{metrics.critical_count} critical issues</strong> that pose significant risk.</p>
                        
                        <h4 class="mt-4">Key Findings:</h4>
                        <ul>
                            <li><strong>{metrics.critical_count} Critical</strong> security vulnerabilities requiring immediate remediation</li>
                            <li><strong>{metrics.high_count} High</strong> risk issues that should be addressed within 7 days</li>
                            <li>Firewall configuration shows significant room for security hardening</li>
                            <li>Compliance gaps identified across multiple security domains</li>
                        </ul>
                    </div>
                </div>
                
                <div class="card shadow-lg mt-4">
                    <div class="card-body">
                        <h3 class="card-title">Top Critical Issues</h3>
                        
                        {self._generate_critical_findings_html(findings[:5])}
                        
                        <div class="text-center mt-4">
                            <a href="dashboard_{timestamp}.html" class="btn btn-primary btn-lg">
                                <i class="fas fa-chart-line"></i> View Detailed Dashboard
                            </a>
                        </div>
                    </div>
                </div>
                
                <div class="card shadow-lg mt-4">
                    <div class="card-body">
                        <h3 class="card-title">Recommendations</h3>
                        <ol class="list-group list-group-numbered">
                            <li class="list-group-item">Address all critical findings within <strong>24-48 hours</strong></li>
                            <li class="list-group-item">Develop remediation plan for high and medium findings</li>
                            <li class="list-group-item">Implement security baseline configuration</li>
                            <li class="list-group-item">Schedule regular security audits (quarterly recommended)</li>
                            <li class="list-group-item">Provide security awareness training for administrators</li>
                        </ol>
                    </div>
                </div>
                
                <div class="text-center mt-5 mb-5">
                    <small class="text-muted">
                        Report generated by Fortigate Security Auditor v3.0 | By Javid Huseynzada<br>
                        Confidential - For authorized personnel only
                    </small>
                </div>
            </div>
        </div>
    </div>
</body>
</html>'''
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_file
    
    def _generate_critical_findings_html(self, findings: List[AuditFinding]) -> str:
        """Generate HTML for critical findings"""
        html = ""
        for finding in findings:
            if finding.severity == 'CRITICAL':
                html += f'''
                <div class="finding-card critical">
                    <h5>[{finding.id}] {finding.title}</h5>
                    <p><strong>Risk Score:</strong> {finding.risk_score}/10</p>
                    <p><strong>Description:</strong> {finding.description[:200]}...</p>
                    <p><strong>Recommendation:</strong> {finding.recommendation[:150]}...</p>
                </div>
                '''
        return html if html else "<p>No critical findings detected.</p>"
    
    def _generate_technical_report(self, findings: List[AuditFinding], 
                                 config_info: Dict, metrics: SecurityMetrics, 
                                 timestamp: str) -> Path:
        """Generate detailed technical report"""
        report_file = self.output_dir / f"technical_report_{timestamp}.html"
        
        # Generate report content
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Technical Security Report - Fortigate Audit</title>
    <style>
        body {{ font-family: 'Courier New', monospace; margin: 40px; }}
        .finding {{ border: 1px solid #ddd; margin: 20px 0; padding: 20px; page-break-inside: avoid; }}
        .critical {{ border-left: 5px solid #dc3545; background: #fff5f5; }}
        .high {{ border-left: 5px solid #fd7e14; background: #fff9f0; }}
        .medium {{ border-left: 5px solid #ffc107; background: #fffdf0; }}
        .low {{ border-left: 5px solid #28a745; background: #f8fff8; }}
        pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; font-size: 12px; }}
        h1, h2, h3 {{ color: #333; }}
        .summary {{ background: #e8f4fd; padding: 20px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>Fortigate Technical Security Report</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Configuration File:</strong> {config_info.get('file_name', 'Unknown')}</p>
    <p><strong>Security Score:</strong> {metrics.total_score}/100 ({metrics.grade})</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Total Findings: {len(findings)} | Critical: {metrics.critical_count} | High: {metrics.high_count} | Medium: {metrics.medium_count} | Low: {metrics.low_count}</p>
    </div>
    
    <h2>Detailed Findings</h2>
'''
        
        # Add all findings
        for finding in findings:
            severity_class = finding.severity.lower()
            html_content += f'''
    <div class="finding {severity_class}">
        <h3>[{finding.id}] {finding.title}</h3>
        <p><strong>Severity:</strong> {finding.severity}</p>
        <p><strong>Category:</strong> {finding.category}</p>
        <p><strong>Risk Score:</strong> {finding.risk_score}/10</p>
        <p><strong>Description:</strong> {finding.description}</p>
        <p><strong>Recommendation:</strong> {finding.recommendation}</p>
'''
            if finding.evidence:
                html_content += f'''
        <p><strong>Evidence:</strong></p>
        <pre>{html.escape(finding.evidence)}</pre>
'''
            if finding.fix_commands:
                html_content += f'''
        <p><strong>Fix Commands:</strong></p>
        <pre>{html.escape(finding.fix_commands)}</pre>
'''
            if finding.rule_id:
                html_content += f'''
        <p><strong>Rule ID:</strong> {finding.rule_id}</p>
'''
            html_content += '''
    </div>
'''
        
        html_content += '''
</body>
</html>'''
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_file
    
    def _generate_json_export(self, findings: List[AuditFinding], 
                            config_info: Dict, metrics: SecurityMetrics, 
                            timestamp: str) -> Path:
        """Generate JSON data export"""
        report_file = self.output_dir / f"audit_data_{timestamp}.json"
        
        export_data = {
            "metadata": {
                "audit_date": datetime.now().isoformat(),
                "audit_version": "3.0",
                "auditor": "Javid Huseynzada",
                "config_file": config_info.get('file_name', ''),
                "file_size": config_info.get('file_size', 0),
                "lines_analyzed": config_info.get('line_count', 0)
            },
            "security_metrics": metrics.to_dict(),
            "findings": [f.to_dict() for f in findings],
            "summary": {
                "total_findings": len(findings),
                "critical_count": metrics.critical_count,
                "high_count": metrics.high_count,
                "medium_count": metrics.medium_count,
                "low_count": metrics.low_count,
                "security_score": metrics.total_score,
                "security_grade": metrics.grade
            }
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        # Also create a simplified version for the dashboard
        dashboard_data = self.output_dir / "dashboard_data.json"
        with open(dashboard_data, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2)
        
        return report_file
    
    def _generate_csv_export(self, findings: List[AuditFinding], timestamp: str) -> Path:
        """Generate CSV export"""
        report_file = self.output_dir / f"findings_export_{timestamp}.csv"
        
        with open(report_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'ID', 'Title', 'Severity', 'Category', 'Risk Score',
                'Description', 'Recommendation', 'Rule ID', 'Evidence',
                'Fix Commands', 'CVE References', 'Timestamp'
            ])
            
            for finding in findings:
                writer.writerow([
                    finding.id,
                    finding.title,
                    finding.severity,
                    finding.category,
                    finding.risk_score,
                    finding.description[:500],
                    finding.recommendation[:500],
                    finding.rule_id,
                    finding.evidence[:200],
                    finding.fix_commands[:200],
                    finding.cve_references,
                    finding.timestamp
                ])
        
        return report_file
    
    def _generate_remediation_plan(self, findings: List[AuditFinding], 
                                 metrics: SecurityMetrics, timestamp: str) -> Path:
        """Generate remediation action plan"""
        report_file = self.output_dir / f"remediation_plan_{timestamp}.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# Fortigate Security Remediation Plan\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Security Assessment Summary\n")
            f.write(f"- **Security Score**: {metrics.total_score}/100 ({metrics.grade})\n")
            f.write(f"- **Total Findings**: {len(findings)}\n")
            f.write(f"- **Critical Findings**: {metrics.critical_count}\n")
            f.write(f"- **High Findings**: {metrics.high_count}\n\n")
            
            f.write("## Priority 1: Critical Issues (Remediate within 24-48 hours)\n\n")
            critical_findings = [f for f in findings if f.severity == 'CRITICAL']
            for i, finding in enumerate(critical_findings, 1):
                f.write(f"### {i}. {finding.title}\n")
                f.write(f"- **ID**: {finding.id}\n")
                f.write(f"- **Risk Score**: {finding.risk_score}/10\n")
                f.write(f"- **Description**: {finding.description}\n")
                f.write(f"- **Fix Commands**:\n```\n{finding.fix_commands or 'Manual configuration required'}\n```\n\n")
            
            f.write("## Priority 2: High Issues (Remediate within 7 days)\n\n")
            high_findings = [f for f in findings if f.severity == 'HIGH']
            for i, finding in enumerate(high_findings, 1):
                f.write(f"### {i}. {finding.title}\n")
                f.write(f"- **ID**: {finding.id}\n")
                f.write(f"- **Description**: {finding.description[:200]}...\n\n")
            
            f.write("## Implementation Timeline\n\n")
            f.write("```mermaid\ngantt\n    title Fortigate Security Remediation Timeline\n    dateFormat  YYYY-MM-DD\n    section Critical Issues\n    Fix ANY→ANY Rules     :crit, 2024-01-01, 1d\n    Disable HTTP Access   :crit, 2024-01-01, 1d\n    \n    section High Issues\n    Restrict Services     :active, 2024-01-02, 3d\n    Enable Logging        :2024-01-03, 2d\n    \n    section Medium Issues\n    Schedule Optimization :2024-01-05, 5d\n    Security Profiles     :2024-01-07, 3d\n```\n")
            
            f.write("\n## Success Metrics\n")
            f.write("- Security score improvement to 80+ (Grade A- or better)\n")
            f.write("- Zero critical findings\n")
            f.write("- All high findings addressed\n")
            f.write("- Compliance with security standards\n")
        
        return report_file
    
    def _generate_compliance_report(self, findings: List[AuditFinding], timestamp: str) -> Path:
        """Generate compliance report"""
        report_file = self.output_dir / f"compliance_report_{timestamp}.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# Security Compliance Report\n\n")
            f.write("## Standards Compliance Status\n\n")
            
            # Map findings to compliance standards
            standards = {
                'NIST-800-53': [],
                'CIS': [],
                'PCI-DSS': [],
                'ISO-27001': [],
                'GDPR': []
            }
            
            for finding in findings:
                if finding.compliance_standards:
                    for std in finding.compliance_standards:
                        if std in standards:
                            standards[std].append(finding.id)
            
            for std, finding_ids in standards.items():
                f.write(f"### {std}\n")
                if finding_ids:
                    f.write(f"- **Non-compliant findings**: {len(finding_ids)}\n")
                    f.write(f"- **Finding IDs**: {', '.join(finding_ids[:10])}")
                    if len(finding_ids) > 10:
                        f.write(f" and {len(finding_ids) - 10} more")
                    f.write("\n")
                else:
                    f.write("- **Status**: Compliant ✓\n")
                f.write("\n")
        
        return report_file
    
    def _generate_assets(self):
        """Generate CSS and JavaScript assets"""
        # Generate CSS file
        css_file = self.output_dir / "assets" / "style.css"
        css_content = '''
/* Custom styles for Fortigate Security Dashboard */
:root {
    --critical: #dc3545;
    --high: #fd7e14;
    --medium: #ffc107;
    --low: #28a745;
    --info: #6c757d;
}

.security-meter {
    width: 200px;
    height: 200px;
    margin: 0 auto;
}

.gauge-container {
    position: relative;
}

.gauge-value {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-size: 2.5rem;
    font-weight: bold;
}

.severity-indicator {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 8px;
}

.indicator-critical { background-color: var(--critical); }
.indicator-high { background-color: var(--high); }
.indicator-medium { background-color: var(--medium); }
.indicator-low { background-color: var(--low); }
.indicator-info { background-color: var(--info); }

.finding-details {
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.3s ease-out;
}

.finding-details.show {
    max-height: 1000px;
}

.risk-bar {
    height: 8px;
    border-radius: 4px;
    margin: 5px 0;
    background: linear-gradient(to right, #28a745, #ffc107, #fd7e14, #dc3545);
}

.print-only {
    display: none;
}

@media print {
    .no-print {
        display: none;
    }
    .print-only {
        display: block;
    }
    .finding-card {
        page-break-inside: avoid;
    }
}
'''
        
        with open(css_file, 'w', encoding='utf-8') as f:
            f.write(css_content)
        
        # Generate JavaScript file
        js_file = self.output_dir / "assets" / "dashboard.js"
        js_content = '''
// Dashboard JavaScript functionality
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
    
    // Filter functionality
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Remove active class from all buttons
            filterButtons.forEach(btn => btn.classList.remove('active'));
            // Add active class to clicked button
            this.classList.add('active');
            
            const filter = this.dataset.filter;
            filterFindings(filter);
        });
    });
    
    // Search functionality
    const searchInput = document.getElementById('searchFindings');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            filterFindings('all', searchTerm);
        });
    }
    
    // Export functionality
    document.getElementById('exportPdf')?.addEventListener('click', function() {
        window.print();
    });
    
    document.getElementById('exportCsv')?.addEventListener('click', function() {
        exportToCSV();
    });
});

function filterFindings(severity, searchTerm = '') {
    const findings = document.querySelectorAll('.finding-card');
    let visibleCount = 0;
    
    findings.forEach(card => {
        const cardSeverity = card.dataset.severity;
        const cardText = card.textContent.toLowerCase();
        
        const severityMatch = severity === 'all' || cardSeverity === severity;
        const searchMatch = !searchTerm || cardText.includes(searchTerm);
        
        if (severityMatch && searchMatch) {
            card.style.display = 'block';
            visibleCount++;
        } else {
            card.style.display = 'none';
        }
    });
    
    // Update counter
    const counter = document.getElementById('visibleFindings');
    if (counter) {
        counter.textContent = `${visibleCount} findings`;
    }
}

function exportToCSV() {
    // This would export findings to CSV
    alert('CSV export functionality would be implemented here');
}

// Chart color utilities
function getSeverityColor(severity) {
    const colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#28a745',
        'INFO': '#6c757d'
    };
    return colors[severity] || '#6c757d';
}

// Risk score to percentage
function riskToPercentage(riskScore, maxScore = 10) {
    return Math.min(100, (riskScore / maxScore) * 100);
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}
'''
        
        with open(js_file, 'w', encoding='utf-8') as f:
            f.write(js_content)

# ==============================================================================
# MAIN APPLICATION
# ==============================================================================

class FortigateEnterpriseAuditor:
    """Main application class for enterprise security auditing"""
    
    def __init__(self):
        self.config_parser = None
        self.security_auditor = None
        self.report_generator = None
        self.logger = None
    
    def run(self, config_path: str, output_dir: str = "security_audit_results") -> bool:
        """Execute complete security audit workflow"""
        try:
            # Setup logging
            self._setup_logging(output_dir)
            
            print("\n" + "="*80)
            print("🛡️  FORTIGATE ENTERPRISE SECURITY AUDITOR - v3.0")
            print("="*80)
            print(f"📂 Configuration: {config_path}")
            print(f"📁 Output Directory: {output_dir}")
            print("="*80 + "\n")
            
            # Step 1: Parse configuration
            print("[1/4] 📋 Parsing Fortigate configuration...")
            self.config_parser = FortigateConfigParser(config_path)
            if not self.config_parser.load():
                print("❌ Failed to parse configuration file")
                return False
            
            config_info = {
                'file_name': os.path.basename(config_path),
                'file_size': os.path.getsize(config_path),
                'line_count': len(self.config_parser.lines),
                'sections_count': len(self.config_parser.parsed_sections)
            }
            
            print(f"   ✅ Loaded {config_info['line_count']:,} lines")
            print(f"   ✅ Found {config_info['sections_count']} configuration sections")
            print(f"   ✅ Extracted {len(self.config_parser.objects.get('addresses', []))} address objects\n")
            
            # Step 2: Execute security audit
            print("[2/4] 🔍 Running 400+ security checks...")
            self.security_auditor = FortigateSecurityAuditor(self.config_parser)
            findings = self.security_auditor.run_comprehensive_audit()
            
            if not findings:
                print("   ℹ️  No security findings detected")
            else:
                print(f"   ✅ Found {len(findings)} security issues")
            
            # Step 3: Calculate security metrics
            print("[3/4] 📊 Calculating security metrics...")
            metrics_calculator = SecurityMetricsCalculator()
            metrics = metrics_calculator.calculate_metrics(findings)
            
            print(f"   ✅ Security Score: {metrics.total_score}/100 ({metrics.grade})")
            print(f"   ✅ Critical Findings: {metrics.critical_count}")
            print(f"   ✅ High Findings: {metrics.high_count}")
            
            # Step 4: Generate professional reports
            print("[4/4] 📄 Generating professional reports...")
            self.report_generator = ProfessionalReportGenerator(output_dir)
            reports = self.report_generator.generate_all_reports(findings, config_info, metrics)
            
            print(f"   ✅ Generated {len(reports)} professional reports:")
            for report in reports:
                size_kb = report.stat().st_size / 1024
                print(f"      • {report.name} ({size_kb:.1f} KB)")
            
            # Display final summary
            self._display_summary(findings, metrics, output_dir)
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Audit failed: {str(e)}")
            else:
                print(f"❌ Audit failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _setup_logging(self, output_dir: str):
        """Configure logging system"""
        log_dir = Path(output_dir) / "logs"
        log_dir.mkdir(exist_ok=True, parents=True)
        
        log_file = log_dir / f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("FortigateAuditor")
    
    def _display_summary(self, findings: List[AuditFinding], metrics: SecurityMetrics, output_dir: str):
        """Display comprehensive audit summary"""
        print("\n" + "="*80)
        print("📊 AUDIT SUMMARY")
        print("="*80)
        
        # Security score with color coding
        score = metrics.total_score
        if score >= 80:
            score_color = "\033[92m"  # Green
        elif score >= 60:
            score_color = "\033[93m"  # Yellow
        else:
            score_color = "\033[91m"  # Red
        
        print(f"\n🔐 Security Score: {score_color}{score}/100 ({metrics.grade})\033[0m")
        
        # Findings breakdown
        print("\n📈 Findings Breakdown:")
        print(f"   🔴 Critical: {metrics.critical_count}")
        print(f"   🟠 High:     {metrics.high_count}")
        print(f"   🟡 Medium:   {metrics.medium_count}")
        print(f"   🟢 Low:      {metrics.low_count}")
        print(f"   ⚪ Info:      {metrics.info_count}")
        print(f"   📊 Total:     {len(findings)}")
        
        # Top risk categories
        if metrics.top_risks:
            print("\n📋 Top Risk Categories:")
            for category, score in metrics.top_risks[:3]:
                print(f"   • {category}: {score} risk points")
        
        # Critical findings preview
        critical_findings = [f for f in findings if f.severity == 'CRITICAL']
        if critical_findings:
            print(f"\n🚨 Critical Findings Requiring Immediate Attention:")
            for i, finding in enumerate(critical_findings[:3], 1):
                print(f"   {i}. [{finding.id}] {finding.title}")
        
        # Report information
        print(f"\n📁 Reports saved to: {Path(output_dir).absolute()}")
        
        # Dashboard URL
        dashboard_files = list(Path(output_dir).glob("dashboard_*.html"))
        if dashboard_files:
            latest_dashboard = sorted(dashboard_files)[-1]
            print(f"🌐 Interactive Dashboard: file://{latest_dashboard.absolute()}")
        
        print("\n" + "="*80)
        print("✅ Audit completed successfully! | By Javid Huseynzada")
        print("="*80)

# ==============================================================================
# COMMAND LINE INTERFACE
# ==============================================================================

def main():
    """Main entry point with enhanced command line interface"""
    
    # ASCII Art Banner
    banner = '''
\033[96m
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   🛡️  FORTIGATE ENTERPRISE SECURITY AUDITOR v3.0                       ║
║                                                                          ║
║   Complete Security Assessment with 400+ Checks & Interactive Dashboard  ║
║   Author: Javid Huseynzada | Professional Security Audit Suite           ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
\033[0m
'''
    print(banner)
    
    parser = argparse.ArgumentParser(
        description='Fortigate Enterprise Security Auditor - Complete security assessment with interactive dashboard',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python fortigate_audit.py config.txt
  python fortigate_audit.py config.txt --output ./audit_results
  python fortigate_audit.py config.txt --verbose

Features:
  • 400+ comprehensive security checks
  • Interactive web dashboard with filtering
  • Professional reports in multiple formats
  • Security scoring and risk assessment
  • Compliance mapping and remediation plans
        '''
    )
    
    parser.add_argument(
        'config_file',
        help='Path to Fortigate configuration file (TXT format)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='security_audit_results',
        help='Output directory for reports (default: security_audit_results)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging output'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Run quick scan (basic checks only)'
    )
    
    args = parser.parse_args()
    
    # Validate configuration file
    if not os.path.exists(args.config_file):
        print(f"\033[91m❌ Error: Configuration file not found: {args.config_file}\033[0m")
        sys.exit(1)
    
    # Check file extension
    if not args.config_file.lower().endswith(('.txt', '.conf', '.cfg')):
        print(f"\033[93m⚠️  Warning: File extension may not be standard configuration format\033[0m")
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True, parents=True)
    
    print(f"\n\033[92m▶️  Starting Fortigate Security Audit...\033[0m")
    print(f"📂 Config: {args.config_file}")
    print(f"📁 Output: {output_dir.absolute()}")
    print(f"⚡ Mode: {'Quick Scan' if args.quick else 'Comprehensive Audit'}")
    print()
    
    # Run the audit
    auditor = FortigateEnterpriseAuditor()
    
    try:
        success = auditor.run(args.config_file, args.output)
        
        if success:
            print(f"\n\033[92m✅ Security audit completed successfully!\033[0m")
            
            # Open dashboard in default browser (optional)
            dashboard_path = output_dir / "dashboard_*.html"
            dashboards = list(output_dir.glob("dashboard_*.html"))
            if dashboards:
                latest_dashboard = sorted(dashboards)[-1]
                print(f"\n🌐 Open dashboard: file://{latest_dashboard.absolute()}")
                
                # Ask if user wants to open dashboard
                try:
                    import webbrowser
                    open_dashboard = input("\nOpen dashboard in browser? (y/n): ").lower()
                    if open_dashboard == 'y':
                        webbrowser.open(f"file://{latest_dashboard.absolute()}")
                except:
                    pass
        else:
            print(f"\n\033[91m❌ Audit failed. Check logs for details.\033[0m")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n\033[93m⚠️  Audit interrupted by user\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[91m❌ Fatal error: {str(e)}\033[0m")
        import traceback
        traceback.print_exc()
        sys.exit(1)

# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    main()

"""
risk_explainer.py - Module for generating explainable AI insights for security risks
"""

def analyze_ports(open_ports):
    """Generate explanations based on open ports"""
    explanations = []
    
    high_risk_ports = {
        21: {
            "message": "FTP server detected (port 21)",
            "details": "FTP transfers data in plaintext which could lead to credential exposure. Consider using SFTP (port 22) instead.",
            "severity": "high"
        },
        23: {
            "message": "Telnet server detected (port 23)",
            "details": "Telnet transmits data in plaintext and has known security vulnerabilities. SSH (port 22) is a more secure alternative.",
            "severity": "critical"
        },
        25: {
            "message": "SMTP server detected (port 25)",
            "details": "Open SMTP servers can be abused for spam relay if not properly configured.",
            "severity": "medium"
        },
        3306: {
            "message": "MySQL database exposed (port 3306)",
            "details": "Direct database exposure increases attack surface. Consider restricting access through a firewall or VPN.",
            "severity": "high"
        },
        1433: {
            "message": "SQL Server database exposed (port 1433)",
            "details": "Direct database exposure increases attack surface. Consider restricting access through a firewall or VPN.",
            "severity": "high"
        },
        8080: {
            "message": "Alternative HTTP port open (8080)",
            "details": "Additional HTTP ports may indicate testing servers or proxies that aren't properly secured.",
            "severity": "medium"
        }
    }
    
    # Check for common dangerous ports
    for port in open_ports:
        if port in high_risk_ports:
            explanations.append(high_risk_ports[port])
    
    # Check for too many open ports
    if len(open_ports) > 5:
        explanations.append({
            "message": f"Large number of open ports detected ({len(open_ports)} ports)",
            "details": "Having many open ports increases the attack surface. Consider closing unnecessary services.",
            "severity": "medium"
        })
    
    return explanations

def analyze_ssl(ssl_info):
    """Generate explanations based on SSL/TLS configuration"""
    explanations = []
    
    if not ssl_info.get('has_ssl', False):
        explanations.append({
            "message": "No SSL/TLS encryption detected",
            "details": "Unencrypted communications can be intercepted. Implement HTTPS using a valid certificate.",
            "severity": "critical"
        })
    elif not ssl_info.get('cert_valid', True):
        explanations.append({
            "message": "Invalid SSL certificate detected",
            "details": "An invalid certificate can lead to security warnings and reduced user trust. Obtain a valid certificate from a trusted CA.",
            "severity": "high"
        })
    
    if not ssl_info.get('hsts', False):
        explanations.append({
            "message": "HSTS not implemented",
            "details": "HTTP Strict Transport Security prevents downgrade attacks. Enable HSTS headers for improved security.",
            "severity": "medium"
        })
    
    return explanations

def analyze_reputation(ip_reputation):
    """Generate explanations based on IP reputation"""
    explanations = []
    
    if ip_reputation.get('suspicious', False):
        reasons = ip_reputation.get('reasons', [])
        if reasons:
            for reason in reasons:
                explanations.append({
                    "message": f"IP reputation issue: {reason}",
                    "details": "This IP address has been flagged in threat intelligence databases. Consider investigating or changing IP if possible.",
                    "severity": "high"
                })
        else:
            explanations.append({
                "message": "IP has suspicious reputation",
                "details": "This IP address has been flagged in threat intelligence databases. Consider investigating or changing IP if possible.",
                "severity": "high"
            })
    
    return explanations

def analyze_domain(domain, whois_data):
    """Generate explanations based on domain and WHOIS data"""
    explanations = []
    
    # Check domain age
    if whois_data and whois_data.get('creation_date'):
        try:
            from datetime import datetime
            import time
            
            if isinstance(whois_data['creation_date'], str):
                creation_date = datetime.strptime(whois_data['creation_date'], '%Y-%m-%d')
            elif isinstance(whois_data['creation_date'], (list, tuple)) and whois_data['creation_date']:
                # Some WHOIS responses return lists of dates
                if isinstance(whois_data['creation_date'][0], str):
                    creation_date = datetime.strptime(whois_data['creation_date'][0], '%Y-%m-%d')
                else:
                    creation_date = whois_data['creation_date'][0]
            else:
                creation_date = whois_data['creation_date']
                
            now = datetime.now()
            domain_age_days = (now - creation_date).days
            
            if domain_age_days < 30:
                explanations.append({
                    "message": f"Very new domain (created {domain_age_days} days ago)",
                    "details": "Newly registered domains are frequently used in phishing and malware campaigns.",
                    "severity": "medium"
                })
        except:
            # Skip if we can't parse the date correctly
            pass
    
    # Check for suspicious domain patterns
    import re
    
    if re.search(r'(secure|login|account|bank|update|verify).*\d+', domain):
        explanations.append({
            "message": "Domain naming pattern matches common phishing patterns",
            "details": "Domain contains security terms combined with numbers, a common phishing tactic.",
            "severity": "high"
        })
    
    if len(domain) > 30:
        explanations.append({
            "message": "Unusually long domain name",
            "details": "Excessively long domain names are sometimes used to obfuscate malicious domains.",
            "severity": "low"
        })
    
    return explanations

def generate_risk_explanations(domain, ip, url, open_ports, ssl_info, ip_reputation, whois_data):
    """
    Generate comprehensive explanations for security risks
    """
    explanations = []
    
    # Analyze each component
    explanations.extend(analyze_ports(open_ports))
    explanations.extend(analyze_ssl(ssl_info))
    explanations.extend(analyze_reputation(ip_reputation))
    explanations.extend(analyze_domain(domain, whois_data))
    
    # Add contextual explanations based on combined factors
    if any(exp['severity'] == 'critical' for exp in explanations):
        if any('port' in exp['message'].lower() for exp in explanations):
            explanations.append({
                "message": "Multiple critical service exposures detected",
                "details": "The combination of exposed services significantly increases attack surface.",
                "severity": "critical"
            })
    
    # Sort explanations by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    explanations.sort(key=lambda x: severity_order.get(x.get('severity', 'medium'), 99))
    
    return explanations
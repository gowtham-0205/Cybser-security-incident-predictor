// mitigationGenerator.js
// Functions to generate appropriate mitigation strategies based on scan results

export const generateMitigations = (scanResult) => {
    if (!scanResult) return [];
    
    const mitigations = [];
    
    // Process port-related risks
    if (scanResult.openPorts) {
      processPorts(scanResult.openPorts, mitigations);
    }
    
    // Process SSL/TLS risks
    if (scanResult.ssl_info) {
      processSSL(scanResult.ssl_info, mitigations);
    }
    
    // Process reputation risks
    if (scanResult.reputation === 'Suspicious') {
      processReputationRisks(mitigations);
    }
    
    // Add generic WAF rules if risk is medium or high
    if (scanResult.risk_level === 'Medium' || scanResult.risk_level === 'High') {
      addWAFRules(mitigations);
    }
    
    return mitigations;
  };
  
  // Process open ports and provide mitigation strategies
  function processPorts(openPorts, mitigations) {
    // Check for SSH port
    if (openPorts.includes(22)) {
      mitigations.push({
        type: 'firewall',
        title: 'Secure SSH Port',
        description: 'Your SSH port (22) is open to the internet. Restrict access to specific IP addresses or consider changing to a non-standard port.',
        codeTitle: 'UFW Firewall Rule',
        code: 'sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp'
      });
      
      mitigations.push({
        type: 'script',
        title: 'SSH Hardening Script',
        description: 'Implement SSH key-based authentication and disable password login',
        codeTitle: 'SSH Security Script',
        code: `#!/bin/bash
  # Backup original config
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
  
  # Disable password authentication
  sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  
  # Disable root login
  sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
  
  # Change SSH port (optional)
  sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
  
  # Restart SSH service
  systemctl restart sshd`
      });
    }
    
    // Check for database ports
    if (openPorts.includes(3306)) {
      mitigations.push({
        type: 'firewall',
        title: 'Secure MySQL Port',
        description: 'Your MySQL port (3306) should not be exposed to the internet. Restrict access to specific IP addresses.',
        codeTitle: 'IPTables Rule',
        code: 'iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 3306 -j ACCEPT\niptables -A INPUT -p tcp --dport 3306 -j DROP'
      });
    }
    
    // Check for common web ports
    if (openPorts.includes(8080)) {
      mitigations.push({
        type: 'network',
        title: 'Secure Alternative HTTP Port',
        description: 'Port 8080 is open and might be used for development or admin interfaces. Consider using a reverse proxy or restricting access.',
        codeTitle: 'Nginx Reverse Proxy Configuration',
        code: `server {
      listen 80;
      server_name example.com;
      
      location / {
          proxy_pass http://localhost:8080;
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          
          # IP restriction
          allow 192.168.1.0/24;
          deny all;
      }
  }`
      });
    }
  }
  
  // Process SSL/TLS issues
  function processSSL(sslInfo, mitigations) {
    if (!sslInfo.has_ssl) {
      mitigations.push({
        type: 'htaccess',
        title: 'Force HTTPS Redirect',
        description: 'Your website is not using SSL/TLS encryption. Force all traffic to use HTTPS for better security.',
        codeTitle: '.htaccess Redirect Rule',
        code: `# Redirect HTTP to HTTPS
  RewriteEngine On
  RewriteCond %{HTTPS} off
  RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`
      });
      
      mitigations.push({
        type: 'script',
        title: 'Let\'s Encrypt SSL Installation',
        description: 'Install a free SSL certificate using Let\'s Encrypt',
        codeTitle: 'Certbot Installation Script',
        code: `#!/bin/bash
  # Install Certbot
  apt-get update
  apt-get install -y certbot python3-certbot-apache
  
  # Get SSL certificate for Apache
  certbot --apache -d example.com -d www.example.com
  
  # Auto-renewal cron job
  echo "0 0,12 * * * root python -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q" | sudo tee -a /etc/crontab > /dev/null`
      });
    } else if (!sslInfo.hsts) {
      mitigations.push({
        type: 'htaccess',
        title: 'Enable HTTP Strict Transport Security (HSTS)',
        description: 'Your site has SSL but is missing HSTS headers which protect against downgrade attacks.',
        codeTitle: '.htaccess HSTS Rule',
        code: `# Enable HSTS (HTTP Strict Transport Security)
  <IfModule mod_headers.c>
      Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  </IfModule>`
      });
    }
  }
  
  // Add security recommendations for domains with reputation issues
  function processReputationRisks(mitigations) {
    mitigations.push({
      type: 'firewall',
      title: 'IP Threat Protection',
      description: 'Your IP has suspicious reputation flags. Implement additional security measures to prevent common attack vectors.',
      codeTitle: 'Advanced Firewall Rules',
      code: `# Block common attack vectors
  iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
  
  # Block suspicious user agents
  iptables -A INPUT -p tcp -m string --string "nikto" --algo bm -j DROP
  iptables -A INPUT -p tcp -m string --string "sqlmap" --algo bm -j DROP`
    });
    
    mitigations.push({
      type: 'htaccess',
      title: 'Web Application Hardening',
      description: 'Implement rules to block common attack patterns and suspicious behavior.',
      codeTitle: '.htaccess Security Rules',
      code: `# Block bad bots
  RewriteEngine On
  RewriteCond %{HTTP_USER_AGENT} ^.*(bot|spider|crawl|slurp).* [NC]
  RewriteRule .* - [F,L]
  
  # Prevent directory listing
  Options -Indexes
  
  # Protect against XSS attacks
  <IfModule mod_headers.c>
      Header set X-XSS-Protection "1; mode=block"
  </IfModule>
  
  # Block access to sensitive files
  <FilesMatch "(\\.htaccess|\\.htpasswd|\\.git|\\.svn|\\.env)">
      Order Allow,Deny
      Deny from all
  </FilesMatch>`
    });
  }
  
  // Add Web Application Firewall rules
  function addWAFRules(mitigations) {
    mitigations.push({
      type: 'script',
      title: 'ModSecurity WAF Installation',
      description: 'Install and configure ModSecurity Web Application Firewall for Apache',
      codeTitle: 'ModSecurity Installation Script',
      code: `#!/bin/bash
  # Install ModSecurity for Apache
  apt-get update
  apt-get install -y libapache2-mod-security2
  
  # Enable ModSecurity
  cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
  
  # Set ModSecurity to detection mode (change to "On" for blocking mode)
  sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
  
  # Download OWASP Core Rule Set
  wget https://github.com/coreruleset/coreruleset/archive/v3.3.2.tar.gz
  tar -xzf v3.3.2.tar.gz
  mv coreruleset-3.3.2 /etc/apache2/modsecurity-crs
  cd /etc/apache2/modsecurity-crs
  cp crs-setup.conf.example crs-setup.conf
  
  # Create ModSecurity configuration in Apache
  cat > /etc/apache2/mods-enabled/security2.conf << 'EOL'
  <IfModule security2_module>
      # Load ModSecurity configuration
      Include /etc/modsecurity/modsecurity.conf
      
      # Load OWASP CRS rules
      Include /etc/apache2/modsecurity-crs/crs-setup.conf
      Include /etc/apache2/modsecurity-crs/rules/*.conf
  </IfModule>
  EOL
  
  # Restart Apache
  systemctl restart apache2`
    });
  }
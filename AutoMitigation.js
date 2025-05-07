import React, { useState } from 'react';
import { Shield, FileLock2, AlertTriangle, Network, FileCode, Copy, Check } from 'lucide-react';

export default function AutoMitigation({ mitigations, scanCompleted, loading }) {
  const [copied, setCopied] = useState({});
  
  const getMitigationIcon = (type) => {
    switch(type) {
      case 'firewall':
        return <Shield size={20} className="mitigation-icon firewall" />;
      case 'htaccess':
        return <FileLock2 size={20} className="mitigation-icon htaccess" />;
      case 'script':
        return <FileCode size={20} className="mitigation-icon script" />;
      case 'network':
        return <Network size={20} className="mitigation-icon network" />;
      default:
        return <AlertTriangle size={20} className="mitigation-icon general" />;
    }
  };

  const copyToClipboard = (code, id) => {
    navigator.clipboard.writeText(code);
    setCopied({ ...copied, [id]: true });
    
    // Reset the copied state after 2 seconds
    setTimeout(() => {
      setCopied({ ...copied, [id]: false });
    }, 2000);
  };

  // Group mitigations by category
  const groupedMitigations = mitigations.reduce((groups, item) => {
    const group = (groups[item.type] || []);
    group.push(item);
    groups[item.type] = group;
    return groups;
  }, {});

  return (
    <div>
      <div className="card-header">
        <h2 className="card-title">Auto-Mitigation Suggestions</h2>
      </div>
      
      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Generating mitigation strategies...</p>
        </div>
      ) : mitigations && mitigations.length > 0 && scanCompleted ? (
        <div className="mitigations-container">
          {Object.entries(groupedMitigations).map(([type, items], groupIndex) => (
            <div key={groupIndex} className="mitigation-group">
              <h3 className="mitigation-group-title">{type.charAt(0).toUpperCase() + type.slice(1)} Protections</h3>
              
              {items.map((item, index) => (
                <div key={`${type}-${index}`} className="mitigation-item">
                  <div className="mitigation-header">
                    {getMitigationIcon(item.type)}
                    <div className="mitigation-title">{item.title}</div>
                  </div>
                  
                  <div className="mitigation-description">
                    {item.description}
                  </div>
                  
                  {item.code && (
                    <div className="mitigation-code-container">
                      <div className="mitigation-code-header">
                        <span>{item.codeTitle || 'Implementation'}</span>
                        <button 
                          className="copy-btn"
                          onClick={() => copyToClipboard(item.code, `${type}-${index}`)}
                        >
                          {copied[`${type}-${index}`] ? (
                            <><Check size={14} /> Copied</>
                          ) : (
                            <><Copy size={14} /> Copy</>
                          )}
                        </button>
                      </div>
                      <pre className="mitigation-code">
                        <code>{item.code}</code>
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-state">
          <p>No mitigation strategies available. Run a scan to get actionable security recommendations.</p>
        </div>
      )}
    </div>
  );
}
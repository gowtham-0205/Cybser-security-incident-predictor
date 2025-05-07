import React from 'react';
import { AlertTriangle, Shield, Server, Lock, Globe, Database, Activity } from 'lucide-react';

function RiskExplanations({ explanations, loading, scanCompleted }) {
  const getExplanationIcon = (explanation) => {
    // Choose appropriate icon based on explanation content
    if (explanation.toLowerCase().includes('port') || explanation.toLowerCase().includes('service'))
      return <Server size={16} className="explanation-icon port" />;
    if (explanation.toLowerCase().includes('ssl') || explanation.toLowerCase().includes('https') || explanation.toLowerCase().includes('certificate'))
      return <Lock size={16} className="explanation-icon ssl" />;
    if (explanation.toLowerCase().includes('firewall') || explanation.toLowerCase().includes('waf'))
      return <Shield size={16} className="explanation-icon waf" />;
    if (explanation.toLowerCase().includes('traffic') || explanation.toLowerCase().includes('rate') || explanation.toLowerCase().includes('behavior'))
      return <Activity size={16} className="explanation-icon rate" />;
    if (explanation.toLowerCase().includes('domain') || explanation.toLowerCase().includes('dns'))
      return <Globe size={16} className="explanation-icon domain" />;
    if (explanation.toLowerCase().includes('database') || explanation.toLowerCase().includes('data'))
      return <Database size={16} className="explanation-icon database" />;
    
    // Default icon for other cases
    return <AlertTriangle size={16} className="explanation-icon other" />;
  };

  // Group explanations by severity
  const groupedExplanations = {
    critical: [],
    high: [],
    medium: [],
    low: []
  };
  
  if (explanations && explanations.length > 0) {
    explanations.forEach(exp => {
      if (exp.severity && groupedExplanations[exp.severity.toLowerCase()]) {
        groupedExplanations[exp.severity.toLowerCase()].push(exp);
      } else {
        // Default to medium if severity not specified
        groupedExplanations.medium.push(exp);
      }
    });
  }

  return (
    <div>
      <div className="card-header">
        <h2 className="card-title">Risk Explanations</h2>
      </div>
      
      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Analyzing risk factors...</p>
        </div>
      ) : explanations && explanations.length > 0 && scanCompleted ? (
        <div className="risk-explanations">
          {/* Critical Issues */}
          {groupedExplanations.critical.length > 0 && (
            <div className="explanation-section critical">
              <h3 className="section-heading">Critical Issues</h3>
              {groupedExplanations.critical.map((exp, i) => (
                <div key={`critical-${i}`} className="explanation-item">
                  {getExplanationIcon(exp.message)}
                  <div className="explanation-content">
                    <div className="explanation-text">{exp.message}</div>
                    {exp.details && <div className="explanation-details">{exp.details}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
          
          {/* High Risk Issues */}
          {groupedExplanations.high.length > 0 && (
            <div className="explanation-section high">
              <h3 className="section-heading">High Risk Issues</h3>
              {groupedExplanations.high.map((exp, i) => (
                <div key={`high-${i}`} className="explanation-item">
                  {getExplanationIcon(exp.message)}
                  <div className="explanation-content">
                    <div className="explanation-text">{exp.message}</div>
                    {exp.details && <div className="explanation-details">{exp.details}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
          
          {/* Medium Risk Issues */}
          {groupedExplanations.medium.length > 0 && (
            <div className="explanation-section medium">
              <h3 className="section-heading">Medium Risk Issues</h3>
              {groupedExplanations.medium.map((exp, i) => (
                <div key={`medium-${i}`} className="explanation-item">
                  {getExplanationIcon(exp.message)}
                  <div className="explanation-content">
                    <div className="explanation-text">{exp.message}</div>
                    {exp.details && <div className="explanation-details">{exp.details}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
          
          {/* Low Risk Issues */}
          {groupedExplanations.low.length > 0 && (
            <div className="explanation-section low">
              <h3 className="section-heading">Low Risk Issues</h3>
              {groupedExplanations.low.map((exp, i) => (
                <div key={`low-${i}`} className="explanation-item">
                  {getExplanationIcon(exp.message)}
                  <div className="explanation-content">
                    <div className="explanation-text">{exp.message}</div>
                    {exp.details && <div className="explanation-details">{exp.details}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        <div className="empty-state">
          <p>No risk analysis available yet. Run a scan to get detailed risk explanations.</p>
        </div>
      )}
    </div>
  );
}

export default RiskExplanations;
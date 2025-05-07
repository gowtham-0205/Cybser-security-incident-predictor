import React from 'react';
import { FilePlus, Download } from 'lucide-react';
import jsPDF from 'jspdf';

export default function ReportGenerator({
  scanResult,
  recommendations,
  whoisData,
  riskExplanations,
  mitigations,
  scanCompleted,
  loading,
}) {
  const hexToRgb = (hex) => {
    const hexClean = hex.replace('#', '');
    const bigint = parseInt(hexClean, 16);
    return [(bigint >> 16) & 255, (bigint >> 8) & 255, bigint & 255];
  };

  const generatePDF = () => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();

    // Title
    doc.setFontSize(22);
    doc.setTextColor(0, 51, 102);
    doc.text('Cybersecurity Scan Report', pageWidth / 2, 20, { align: 'center' });

    doc.setDrawColor(0, 51, 102);
    doc.line(20, 25, pageWidth - 20, 25);

    // Date
    doc.setFontSize(12);
    doc.setTextColor(100, 100, 100);
    doc.text(`Generated on: ${new Date().toLocaleString()}`, pageWidth / 2, 35, { align: 'center' });

    let yPos = 50;

    // Scan Results
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.text('Scan Results', 20, yPos);
    yPos += 10;

    if (scanResult) {
      doc.setFontSize(12);

      doc.text('Risk Level:', 25, yPos);
      const riskColor = scanResult.risk === 'High' ? '#e53e3e' : scanResult.risk === 'Medium' ? '#dd6b20' : '#38a169';
      doc.setTextColor(...hexToRgb(riskColor));
      doc.text(scanResult.risk || 'N/A', 80, yPos);
      yPos += 10;

      doc.setTextColor(0, 0, 0);
      doc.text('Open Ports:', 25, yPos);
      doc.setFontSize(10);
      doc.text(scanResult.openPorts?.join(', ') || 'N/A', 80, yPos);
      yPos += 10;

      doc.setFontSize(12);
      doc.text('IP Reputation:', 25, yPos);
      const reputationColor = scanResult.reputation === 'Suspicious' ? '#e53e3e' : '#38a169';
      doc.setTextColor(...hexToRgb(reputationColor));
      doc.text(scanResult.reputation || 'N/A', 80, yPos);
      yPos += 10;

      doc.setTextColor(0, 0, 0);
      doc.text('Last Updated:', 25, yPos);
      doc.text(scanResult.lastUpdated || 'N/A', 80, yPos);
      yPos += 15;
    }

    // WHOIS Information
    doc.setFontSize(16);
    doc.text('WHOIS Information', 20, yPos);
    yPos += 10;

    if (whoisData) {
      doc.setFontSize(12);

      doc.text('Registrar:', 25, yPos);
      doc.text(whoisData.registrar || 'Not available', 80, yPos);
      yPos += 10;

      doc.text('Creation Date:', 25, yPos);
      doc.text(
        whoisData.creation_date ? new Date(whoisData.creation_date).toLocaleDateString() : 'Not available',
        80,
        yPos
      );
      yPos += 10;

      doc.text('Expiration Date:', 25, yPos);
      doc.text(
        whoisData.expiration_date ? new Date(whoisData.expiration_date).toLocaleDateString() : 'Not available',
        80,
        yPos
      );
      yPos += 10;

      doc.text('Last Updated:', 25, yPos);
      doc.text(
        whoisData.last_updated ? new Date(whoisData.last_updated).toLocaleDateString() : 'Not available',
        80,
        yPos
      );
      yPos += 10;

      doc.text('Name Servers:', 25, yPos);
      if (whoisData.name_servers?.length) {
        yPos += 5;
        whoisData.name_servers.forEach((ns) => {
          doc.text(`• ${ns}`, 30, yPos);
          yPos += 5;
        });
      } else {
        doc.text('No name servers found', 80, yPos);
        yPos += 10;
      }
    } else {
      doc.setFontSize(12);
      doc.text('No WHOIS data available', 25, yPos);
      yPos += 10;
    }

    // Recommendations 
    yPos += 10;
    if (yPos > 250) {
      doc.addPage();
      yPos = 20;
    }

    doc.setFontSize(16);
    doc.text('Security Recommendations', 20, yPos);
    yPos += 10;

    if (recommendations?.length) {
      doc.setFontSize(12);
      recommendations.forEach((rec, index) => {
        doc.text(`${index + 1}. ${rec}`, 25, yPos);
        yPos += 10;
        
        // Add new page if running out of space
        if (yPos > 280) {
          doc.addPage();
          yPos = 20;
        }
      });
      yPos += 5;
    } else {
      doc.setFontSize(12);
      doc.text('No recommendations available', 25, yPos);
      yPos += 15;
    }

    // Footer
    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(10);
      doc.setTextColor(150, 150, 150);
      doc.text(`Page ${i} of ${pageCount}`, pageWidth / 2, doc.internal.pageSize.getHeight() - 10, { align: 'center' });
      doc.text('© 2025 AI-Powered Cybersecurity Incident Predictor', pageWidth / 2, doc.internal.pageSize.getHeight() - 5, { align: 'center' });
    }

    doc.save('cybersecurity-scan-report.pdf');
  };

  return (
    <div>
      <div className="card-header">
        <h2 className="card-title">Scan Report</h2>
      </div>

      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Preparing report data...</p>
        </div>
      ) : scanCompleted ? (
        <div className="report-container">
          <p className="report-description">
            Download a comprehensive PDF report of your security scan results, including findings, WHOIS information, 
            and security recommendations.
          </p>

          <button className="btn btn-primary btn-download" onClick={generatePDF}>
            <Download size={16} className="btn-icon" />
            Download PDF Report
          </button>

          <div className="report-preview">
            <FilePlus size={40} className="report-icon" />
            <div className="report-preview-info">
              <h3>Report Contents:</h3>
              <ul>
                <li>• Security scan results and risk level</li>
                <li>• WHOIS domain information</li>
                <li>• Security recommendations</li>
              </ul>
            </div>
          </div>
        </div>
      ) : (
        <div className="empty-state">
          <p>No report available. Run a scan to generate a downloadable security report.</p>
        </div>
      )}
    </div>
  );
}
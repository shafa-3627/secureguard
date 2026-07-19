// ==========================================
// REPORTS AND EXPORTS UTILITIES
// ==========================================

document.addEventListener('DOMContentLoaded', () => {
  const exportPdfBtn = document.getElementById('btn-export-pdf');
  const exportExcelBtn = document.getElementById('btn-export-excel');
  const exportCsvBtn = document.getElementById('btn-export-csv');

  if (exportPdfBtn) {
    exportPdfBtn.addEventListener('click', () => {
      const { jsPDF } = window.jspdf;
      const doc = new jsPDF();
      
      // Document Style settings
      doc.setFont("Helvetica");
      
      // Document Header Accent Bar
      doc.setFillColor(14, 165, 233); // Cyan
      doc.rect(0, 0, 210, 8, "F");
      
      // Header Title
      doc.setFontSize(22);
      doc.setFont("Helvetica", "bold");
      doc.setTextColor(11, 16, 33);
      doc.text("SECUREGUARD ENTERPRISE", 14, 25);
      doc.setFontSize(12);
      doc.setFont("Helvetica", "normal");
      doc.setTextColor(100, 116, 139);
      doc.text("ENDPOINT DETECTION & RESPONSE REPORT", 14, 31);
      
      // Line separator
      doc.setDrawColor(226, 232, 240);
      doc.line(14, 35, 196, 35);
      
      // Summary Statistics Header
      doc.setFontSize(13);
      doc.setFont("Helvetica", "bold");
      doc.setTextColor(15, 23, 42);
      doc.text("Executive Summary Status", 14, 45);
      
      // Get telemetry metrics from active state
      const empList = Object.values(employees || {});
      const totalUsers = empList.length || 20;
      const activeThreats = empList.filter(e => e.riskScore >= settings.alertThreshold).length;
      const isolated = empList.filter(e => e.status === 'Isolated').length;
      const activeUsb = empList.filter(e => e.usbStatus !== 'No USB Connected' && !e.usbStatus.includes('Blocked')).length;
      const activeAgentCount = empList.filter(e => e.isAgentConnected).length;
      
      doc.setFontSize(10);
      doc.setFont("Helvetica", "normal");
      doc.setTextColor(51, 65, 85);
      
      doc.text(`Total Inspected Workstations: ${totalUsers}`, 16, 52);
      doc.text(`Connected Endpoint Agents: ${activeAgentCount}`, 16, 58);
      doc.text(`Isolated (Quarantined) Workstations: ${isolated}`, 16, 64);
      doc.text(`Active Security Alerts: ${activeThreats}`, 110, 52);
      doc.text(`Active USB Connections: ${activeUsb}`, 110, 58);
      doc.text(`Report Timestamp: ${new Date().toLocaleString()}`, 110, 64);
      
      // Threat Logs Table
      doc.setFontSize(13);
      doc.setFont("Helvetica", "bold");
      doc.setTextColor(15, 23, 42);
      doc.text("Security Anomaly Logs", 14, 78);
      
      let y = 84;
      doc.setFontSize(9);
      
      // Table Header Row Background
      doc.setFillColor(15, 23, 42);
      doc.rect(14, y, 182, 8, "F");
      
      // Draw Table Header Labels
      doc.setTextColor(255, 255, 255);
      doc.setFont("Helvetica", "bold");
      doc.text("Timestamp", 16, y + 5.5);
      doc.text("Employee", 52, y + 5.5);
      doc.text("Security Event Details", 88, y + 5.5);
      doc.text("Risk", 166, y + 5.5);
      doc.text("Action Taken", 176, y + 5.5);
      
      y += 8;
      doc.setTextColor(51, 65, 85);
      doc.setFont("Helvetica", "normal");
      
      const targetLogs = logs || [];
      if (targetLogs.length === 0) {
        doc.text("No security anomalies detected in this session.", 16, y + 6);
      } else {
        targetLogs.slice(0, 22).forEach(log => {
          if (y > 275) {
            doc.addPage();
            
            // Header accent on new page
            doc.setFillColor(14, 165, 233);
            doc.rect(0, 0, 210, 6, "F");
            
            y = 20;
            // Redraw Header
            doc.setFillColor(15, 23, 42);
            doc.rect(14, y, 182, 8, "F");
            doc.setTextColor(255, 255, 255);
            doc.setFont("Helvetica", "bold");
            doc.text("Timestamp", 16, y + 5.5);
            doc.text("Employee", 52, y + 5.5);
            doc.text("Security Event Details", 88, y + 5.5);
            doc.text("Risk", 166, y + 5.5);
            doc.text("Action Taken", 176, y + 5.5);
            y += 8;
            doc.setTextColor(51, 65, 85);
            doc.setFont("Helvetica", "normal");
          }
          
          doc.text(`${log.date} ${log.time}`, 16, y + 5);
          doc.text(log.username, 52, y + 5);
          
          // Truncate long event strings
          const cleanEvent = log.event.length > 40 ? log.event.substring(0, 37) + '...' : log.event;
          doc.text(cleanEvent, 88, y + 5);
          
          doc.text(String(log.risk), 166, y + 5);
          
          const cleanAction = log.actionTaken.length > 15 ? log.actionTaken.substring(0, 13) + '..' : log.actionTaken;
          doc.text(cleanAction, 176, y + 5);
          y += 7.5;
        });
      }
      
      // Footer page count or branding
      doc.setFontSize(8);
      doc.setTextColor(148, 163, 184);
      doc.text("SecureGuard Enterprise v1.0 • Cybersecurity & Telemetry Integrity Division", 14, 287);
      
      doc.save(`secureguard-security-report-${Date.now()}.pdf`);
    });
  }

  if (exportExcelBtn) {
    exportExcelBtn.addEventListener('click', () => {
      const XLSX = window.XLSX;
      
      // Compile rows
      const worksheetRows = [
        ["SecureGuard Enterprise Security Telemetry Log Records"],
        [],
        ["Date", "Time", "Username", "Workstation Device Name", "Recorded Incident", "Risk Score", "Action Taken"]
      ];
      
      const targetLogs = logs || [];
      targetLogs.forEach(log => {
        worksheetRows.push([
          log.date,
          log.time,
          log.username,
          log.deviceName,
          log.event,
          log.risk,
          log.actionTaken
        ]);
      });
      
      const workbook = XLSX.utils.book_new();
      const sheet = XLSX.utils.aoa_to_sheet(worksheetRows);
      
      // Column width configurations
      sheet["!cols"] = [
        { wch: 12 }, // Date
        { wch: 12 }, // Time
        { wch: 15 }, // Username
        { wch: 25 }, // Device Name
        { wch: 45 }, // Security Event
        { wch: 12 }, // Risk Score
        { wch: 25 }  // Action Taken
      ];
      
      XLSX.utils.book_append_sheet(workbook, sheet, "Security Logs");
      XLSX.writeFile(workbook, `secureguard-threat-records-${Date.now()}.xlsx`);
    });
  }

  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => {
      const targetLogs = logs || [];
      let csvContent = "\uFEFF"; // UTF-8 BOM
      csvContent += "Date,Time,Username,Device Name,Security Event,Risk Score,Mitigation Action\n";
      
      targetLogs.forEach(log => {
        const date = `"${log.date.replace(/"/g, '""')}"`;
        const time = `"${log.time.replace(/"/g, '""')}"`;
        const username = `"${log.username.replace(/"/g, '""')}"`;
        const deviceName = `"${log.deviceName.replace(/"/g, '""')}"`;
        const event = `"${log.event.replace(/"/g, '""')}"`;
        const risk = log.risk;
        const action = `"${log.actionTaken.replace(/"/g, '""')}"`;
        
        csvContent += `${date},${time},${username},${deviceName},${event},${risk},${action}\n`;
      });
      
      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      const link = document.createElement("a");
      const url = URL.createObjectURL(blob);
      
      link.setAttribute("href", url);
      link.setAttribute("download", `secureguard-threat-records-${Date.now()}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    });
  }
});

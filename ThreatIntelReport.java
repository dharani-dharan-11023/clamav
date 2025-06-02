public interface ThreatIntelReport {
    ReportData getThreatVerdict();
    ReportData getThreatVerdictWithFileMeta();
    ReportData getThreatMeta();
    ReportData getThreatReport();
    ReportData getThreatReportFullAnalysis();
}

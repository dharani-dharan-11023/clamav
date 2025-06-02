import java.util.Map;

public abstract class AbstractThreatIntelReport implements ThreatIntelReport {

    private ReportData threatVerdict;
    private ReportData threatVerdictWithFileMeta;
    private ReportData threatMeta;
    private ReportData threatReport;
    private ReportData threatReportFullAnalysis;

    public AbstractThreatIntelReport() {
        // Constructor, can be expanded later if dependencies are needed
    }

    public final ReportData generateReport(String scanId, String scanType) {
        Map<String, Object> rawData = fetchDataForScan(scanId);

        this.threatVerdict = new ReportData(processThreatVerdict(rawData));
        this.threatVerdictWithFileMeta = new ReportData(processThreatVerdictWithFileMeta(rawData));
        this.threatMeta = new ReportData(processThreatMeta(rawData));
        this.threatReport = new ReportData(processThreatReport(rawData));
        this.threatReportFullAnalysis = new ReportData(processThreatReportFullAnalysis(rawData));
        
        // Depending on the design, this method could return a comprehensive report object
        // or simply ensure all individual report parts are populated.
        // For now, let's assume it populates the fields and clients will use getters.
        // It could also return a specific default report part, e.g., the full report.
        return this.threatReportFullAnalysis; 
    }

    protected abstract Map<String, Object> fetchDataForScan(String scanId);

    protected abstract String processThreatVerdict(Map<String, Object> rawData);
    protected abstract String processThreatVerdictWithFileMeta(Map<String, Object> rawData);
    protected abstract String processThreatMeta(Map<String, Object> rawData);
    protected abstract String processThreatReport(Map<String, Object> rawData);
    protected abstract String processThreatReportFullAnalysis(Map<String, Object> rawData);

    @Override
    public ReportData getThreatVerdict() {
        if (threatVerdict == null) {
            throw new IllegalStateException("Report data not generated yet. Call generateReport() first.");
        }
        return threatVerdict;
    }

    @Override
    public ReportData getThreatVerdictWithFileMeta() {
        if (threatVerdictWithFileMeta == null) {
            throw new IllegalStateException("Report data not generated yet. Call generateReport() first.");
        }
        return threatVerdictWithFileMeta;
    }

    @Override
    public ReportData getThreatMeta() {
        if (threatMeta == null) {
            throw new IllegalStateException("Report data not generated yet. Call generateReport() first.");
        }
        return threatMeta;
    }

    @Override
    public ReportData getThreatReport() {
        if (threatReport == null) {
            throw new IllegalStateException("Report data not generated yet. Call generateReport() first.");
        }
        return threatReport;
    }

    @Override
    public ReportData getThreatReportFullAnalysis() {
        if (threatReportFullAnalysis == null) {
            throw new IllegalStateException("Report data not generated yet. Call generateReport() first.");
        }
        return threatReportFullAnalysis;
    }
}

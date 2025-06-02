import java.util.HashMap;
import java.util.Map;

public class FileScanReport extends AbstractThreatIntelReport {

    public FileScanReport() {
        super();
    }

    @Override
    protected Map<String, Object> fetchDataForScan(String scanId) {
        // Simulate fetching data for a given scanId
        System.out.println("FileScanReport: Fetching data for scanId: " + scanId);
        Map<String, Object> data = new HashMap<>();
        data.put("verdict", "MALICIOUS");
        data.put("threatLevel", "HIGH");
        data.put("detectedThreats", "Trojan.GenericKDZ.123, Adware.Win32.InstallCore");
        data.put("analysisSummary", "The file exhibits characteristics of a known trojan and adware behavior.");
        data.put("fullReportText", "Detailed analysis shows the file attempting to connect to suspicious IPs (1.2.3.4, 5.6.7.8) and modifying registry keys related to browser settings. Contains payload identified as Trojan.GenericKDZ.123.");
        data.put("fileMeta", new FileMetaData("sample.exe", 204800L, "PE32 executable", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"));
        
        // Add more specific data if scanId is a certain value for testing
        if ("specific_clean_scan_id_123".equals(scanId)) {
            data.put("verdict", "CLEAN");
            data.put("threatLevel", "NONE");
            data.put("detectedThreats", "None");
            data.put("analysisSummary", "The file appears to be clean.");
            data.put("fullReportText", "No malicious indicators found during the scan.");
            data.put("fileMeta", new FileMetaData("document.pdf", 102400L, "PDF document", "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1"));
        }
        return data;
    }

    @Override
    protected String processThreatVerdict(Map<String, Object> rawData) {
        return String.format("Threat Verdict: %s (Level: %s)",
                rawData.get("verdict"), rawData.get("threatLevel"));
    }

    @Override
    protected String processThreatVerdictWithFileMeta(Map<String, Object> rawData) {
        FileMetaData fileMeta = (FileMetaData) rawData.get("fileMeta");
        return String.format("Threat Verdict: %s (Level: %s). File: %s",
                rawData.get("verdict"), rawData.get("threatLevel"), fileMeta.toString());
    }

    @Override
    protected String processThreatMeta(Map<String, Object> rawData) {
        return String.format("Threat Meta: Detected Threats - %s",
                rawData.get("detectedThreats"));
    }

    @Override
    protected String processThreatReport(Map<String, Object> rawData) {
        return String.format("Threat Report Summary: %s",
                rawData.get("analysisSummary"));
    }

    @Override
    protected String processThreatReportFullAnalysis(Map<String, Object> rawData) {
        return String.format("Threat Report Full Analysis: %s",
                rawData.get("fullReportText"));
    }
}

// It's good practice to put classes into packages.
// For this example, we'll assume they are in a default package or a package named 'threatintel'.
// If you created packages for other files, ensure this Main class is in a scope that can access them,
// or use appropriate import statements.

// import threatintel.FileScanReport; // Example if in a package
// import threatintel.ReportData;    // Example if in a package

public class Main {
    public static void main(String[] args) {
        // Demonstrate FileScanReport
        System.out.println("--- Generating File Scan Report ---");
        // Assuming FileScanReport is in the same package or imported.
        // If not, use the fully qualified name, e.g., com.example.FileScanReport
        FileScanReport fileReport = new FileScanReport();

        // Simulate a scan ID
        String fileScanId = "file123";

        // Generate the report data (this calls the template method)
        fileReport.generateReport(fileScanId, "filescan"); // scanType could be used internally by generateReport if needed

        // Retrieve and print each part of the report
        ReportData verdict = fileReport.getThreatVerdict();
        System.out.println(verdict.getData());

        ReportData verdictWithMeta = fileReport.getThreatVerdictWithFileMeta();
        System.out.println(verdictWithMeta.getData());

        ReportData meta = fileReport.getThreatMeta();
        System.out.println(meta.getData());

        ReportData reportSummary = fileReport.getThreatReport();
        System.out.println(reportSummary.getData());

        ReportData fullAnalysis = fileReport.getThreatReportFullAnalysis();
        System.out.println(fullAnalysis.getData());

        System.out.println("\n--- Generating File Scan Report for different ID (simulating clean file) ---");
        FileScanReport fileReport2 = new FileScanReport();
        // Using the specific ID we added for different behavior in FileScanReport
        fileReport2.generateReport("specific_clean_scan_id_123", "filescan"); 
        System.out.println(fileReport2.getThreatVerdict().getData());
        System.out.println(fileReport2.getThreatVerdictWithFileMeta().getData());
        System.out.println(fileReport2.getThreatMeta().getData());


        // Future demonstration for other report types (optional for now)
        /*
        System.out.println("\n--- Generating Domain Scan Report (Placeholder) ---");
        DomainScanReport domainReport = new DomainScanReport();
        domainReport.generateReport("domain123", "domainscan");
        System.out.println(domainReport.getThreatVerdict().getData());
        */
    }
}

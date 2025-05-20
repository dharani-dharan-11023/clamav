# Type-Specific Scanning

This document describes how ClamAV adapts its scanning process based on the identified type of a file. Once the file type is determined, specialized scanning routines are invoked to handle the specific structures and potential threats associated with that type.

## Dispatching Scans with `cli_magic_scan`

The function `cli_magic_scan`, located in `scanners.c`, plays a pivotal role not only in the initial scan orchestration (as described in the "High-Level Scan Flow") but also in dispatching the scan to type-specific handlers. After the file type is identified (e.g., by `cli_determine_fmap_type`), `cli_magic_scan` uses this information to call the appropriate scanning function designed to handle that particular file format.

This dispatch mechanism ensures that files are analyzed by routines that understand their internal structure, allowing for deeper inspection and more effective threat detection.

## Examples of Type-Specific Scanning Functions

ClamAV includes a range of functions tailored for common and often exploited file formats. Below are some prominent examples:

### `cli_scanzip` (ZIP Archives)

*   **Responsibility:** Handles the scanning of ZIP archives and formats based on ZIP, such as OOXML documents, JAR files, and APKs.
*   **Process:** `cli_scanzip` iterates through the files contained within the ZIP archive. For each embedded file, it extracts the content and typically makes a recursive call to `cli_magic_scan`. This allows each file within the archive to be individually typed and scanned according to its own nature. It also checks for archive-specific exploits or malformed structures.

### `cli_scanole2` (OLE2 Containers)

*   **Responsibility:** Scans OLE2 (Object Linking and Embedding) containers, which are compound file formats used by older Microsoft Office documents (e.g., `.doc`, `.xls`, `.ppt`).
*   **Process:** `cli_scanole2` parses the OLE2 structure to identify and extract streams of data within the container. These streams can include macros, embedded objects, or other components. Extracted streams are then recursively scanned, often via `cli_magic_scan`, to detect malicious macros or embedded malware.

### `cli_scanpe` (PE Files - Windows Executables)

*   **Responsibility:** Specialized in scanning Portable Executable (PE) files, which are the standard format for executables, DLLs, and other object files on Windows.
*   **Process:** `cli_scanpe` parses the PE header and various sections of the executable. It looks for known malware indicators, checks for packers (software used to compress or obfuscate executables), analyzes import/export tables, and may perform heuristic analysis specific to executable code. It can also extract resources or embedded executables for further recursive scanning.

### `cli_scanelf` (ELF Files - Linux Executables)

*   **Responsibility:** Handles the scanning of Executable and Linkable Format (ELF) files, the standard executable format for Linux and other Unix-like systems.
*   **Process:** Similar to `cli_scanpe`, `cli_scanelf` parses ELF headers and sections. It identifies characteristics of malicious ELF files, checks for packers, and analyzes segments and sections for suspicious code or data. Embedded components can also be extracted and recursively scanned.

### `cli_scanhtml` (HTML Files)

*   **Responsibility:** Scans HTML files, which are common vectors for phishing, drive-by downloads, and malicious scripts.
*   **Process:** `cli_scanhtml` parses HTML content, looking for malicious JavaScript, VBScript, or other embedded scripts. It identifies suspicious URLs, iframe injections, and techniques used to obfuscate malicious code. It may also extract and scan linked resources or embedded objects.

### `cli_scanpdf` (PDF Documents)

*   **Responsibility:** Scans Portable Document Format (PDF) files, which are frequently used to distribute malware through embedded scripts, exploits for PDF reader vulnerabilities, or malicious links.
*   **Process:** `cli_scanpdf` parses the PDF structure, which can be complex. It looks for embedded JavaScript, actions triggered by events (e.g., opening the document), obfuscated objects, and known PDF exploits. It extracts and recursively scans embedded content, such as images or other file types, that might be hidden within the PDF.

## Core Responsibilities of Type-Specific Scanners

While each type-specific scanning function is tailored to a particular file format, they generally share common core responsibilities:

*   **Parsing Format-Specific Structures:** Understanding and navigating the unique layout, headers, metadata, and data segments of the file type.
*   **Content Extraction:** Extracting embedded objects, streams, scripts, or other files contained within the primary file. For example, extracting files from an archive, macros from a document, or scripts from an HTML page.
*   **Recursive Scanning:** Crucially, after extracting embedded content, these functions often make recursive calls to `cli_magic_scan` (or directly to other appropriate scanners). This ensures that each component, no matter how deeply nested, is thoroughly analyzed.
*   **Applying Targeted Heuristics:** Employing detection logic and heuristics that are specifically relevant to the vulnerabilities and malicious patterns associated with that file type.
*   **Flagging Malformations:** Identifying malformed file structures that might indicate an attempt to evade detection or exploit parser vulnerabilities.

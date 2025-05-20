# File Typing Process

This document describes the file typing process within the ClamAV engine. Accurate file type identification is crucial for applying the correct scanning techniques and for detecting threats effectively.

## `cli_determine_fmap_type`: The Core of File Typing

The primary function responsible for file type identification in ClamAV is `cli_determine_fmap_type`, located in `filetypes.c`. This function takes a memory-mapped file (`fmap_t`) as input and attempts to determine its type by employing several methods. The order and specifics of these methods are designed to balance accuracy and performance.

## Magic Number Matching

One of the fundamental techniques used by `cli_determine_fmap_type` is magic number matching. Magic numbers are sequences of bytes at the beginning of a file (or specific offsets) that uniquely identify a file type. ClamAV utilizes two main sources for these magic numbers:

*   **`engine->ftypes`**: This likely refers to a collection of file type signatures that are more general or broadly applicable. These signatures help in identifying common file formats.
*   **`engine->ptypes`**: This might refer to "portable types" or "platform types," possibly indicating signatures for file types that have consistent representations across different operating systems or architectures.

The engine compares the initial bytes of the input file with the magic numbers stored in these structures. If a match is found, the corresponding file type is identified.

## Aho-Corasick for Efficient Type Identification

For more complex scenarios or when dealing with a large set of potential patterns (beyond simple magic numbers), ClamAV employs the Aho-Corasick algorithm. This algorithm is highly efficient for searching for multiple patterns (substrings) simultaneously within a given text (in this case, the file content).

The Aho-Corasick automaton is typically pre-built from a dictionary of type-specific patterns. `cli_determine_fmap_type` uses this automaton to quickly find occurrences of these patterns in the file data, which aids in identifying the file type, especially for formats that might not have a single, fixed magic number at the very beginning.

## Special Handling for Specific File Formats

Beyond generic magic number matching and Aho-Corasick, ClamAV incorporates special handling routines for certain file formats that require more sophisticated analysis for accurate identification.

### OOXML Documents

Office Open XML (OOXML) documents (e.g., `.docx`, `.xlsx`, `.pptx`) are essentially ZIP archives containing various XML files and other resources. Simply identifying an OOXML file as a ZIP archive is not sufficient. ClamAV performs deeper inspection by:

*   Looking for specific internal ZIP entry names that are characteristic of OOXML documents (e.g., `[Content_Types].xml`, `_rels/.rels`).
*   This allows the engine to distinguish OOXML files from generic ZIP archives and apply targeted scanning logic for Microsoft Office documents.

### Plain Text Files (`cli_texttype`)

Identifying plain text files can also be nuanced. The `cli_texttype` function (or a similar mechanism) is used to determine if a file is a plain text file. This process might involve:

*   Checking for the absence of common binary file magic numbers.
*   Analyzing the byte content for characteristics typical of text, such as the prevalence of printable ASCII characters, line feed patterns, and UTF-8 sequences.
*   This helps in correctly classifying scripts, configuration files, email bodies, and other text-based formats, ensuring they are processed appropriately.

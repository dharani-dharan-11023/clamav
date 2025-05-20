# `scanraw` and Embedded Object Scanning

This document explains the role and functionality of the `scanraw` function within ClamAV, particularly its significance in generic data scanning and the detection and processing of embedded objects.

## The `scanraw` Function: Purpose and Usage

The `scanraw` function, typically located in `scanners.c`, serves as a versatile scanning routine for raw data streams. Its primary purpose is to apply general-purpose scanning techniques to data that may not have a recognized, specific file structure or when a dedicated parser for an identified file type has completed its primary analysis and further byte-level scanning is required.

Key scenarios where `scanraw` is utilized include:

*   **Fallback Scanning:** When `cli_determine_fmap_type` cannot identify a file's type, `scanraw` can be used to perform a generic scan of its content.
*   **Post-Parser Scanning:** After a type-specific parser (e.g., `cli_scanzip`, `cli_scanpdf`) has processed a file, `scanraw` might be called on the entire file content or specific extracted streams to catch anything missed by the specialized parser or to look for generic patterns.
*   **Scanning Data Fragments:** It can be applied to arbitrary chunks of data, such as those extracted from network streams or memory dumps.

## Generic Scanning with `scanraw`

When operating in a generic scanning mode, `scanraw` typically employs broad detection methods that are not reliant on a specific file structure. This often involves:

*   **Applying General-Purpose Signatures:** Running pattern matching algorithms (like Aho-Corasick or Boyer-Moore with a general signature set) across the entire data stream.
*   **Heuristic Analysis:** Using heuristics that look for suspicious byte sequences or characteristics that are indicative of malware but not tied to a particular file format.
*   **Hash Matching:** Comparing hashes of the data (or parts of it) against databases of known malicious content.

This ensures that even if a file's specific type is unknown or if it's a custom format, ClamAV can still attempt to find threats within it.

## Identifying Embedded Objects within Raw Data

A crucial capability of `scanraw` (or functions called by it) is its ability to perform file type recognition *within* the raw data stream it is analyzing. This is essential for detecting embedded objects that might be hidden or obfuscated within a larger, seemingly innocuous file or data blob.

For example, `scanraw` might:

*   Search for common file signatures (magic numbers) at various offsets within the data stream. This could identify a PE file header (e.g., "MZ") appearing unexpectedly within a data file, suggesting an embedded executable.
*   Use pattern matching to find characteristic byte sequences of container formats or compressed data.

If `scanraw` successfully identifies a known file type signature within the data it's processing, it recognizes this segment as a potential embedded object.

## Recursive Scanning of Identified Embedded Objects

Upon identifying a potential embedded object (e.g., finding PE file signatures inside a data blob), `scanraw` does not typically handle the specialized scanning of that object itself. Instead, it triggers a recursive scanning process.

This is generally achieved by:

1.  **Isolating the Embedded Object:** The segment of data recognized as the embedded object is demarcated.
2.  **Invoking `cli_magic_scan` (or `cli_magic_scan_nested_fmap_type`):** A new scan is initiated specifically for this isolated data segment.
    *   `cli_magic_scan` would be called if the embedded object can be treated as a new, independent file.
    *   `cli_magic_scan_nested_fmap_type` (or a similar function) might be used to handle the context of the embedded object more specifically, indicating its nested nature. This function would then proceed with file typing and dispatching to the appropriate type-specific scanner (e.g., `cli_scanpe` for an embedded PE file).

This recursive approach ensures that embedded files are not just detected by `scanraw` but are also passed to the most appropriate specialized scanning routines for thorough analysis, maintaining the depth and accuracy of the ClamAV scanning process. For instance, if `scanraw` finds a PE file signature, it will effectively hand off that portion of the data to `cli_scanpe` via a new `cli_magic_scan` call.

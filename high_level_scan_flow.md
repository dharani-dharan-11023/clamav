# High-Level Scan Flow

This document outlines the high-level flow of a scan within the ClamAV engine. It describes the main entry points, the central role of key functions, and important data structures used in the scanning process.

## Entry Points

The ClamAV engine provides several entry points for initiating a scan, depending on the type of input and the desired scanning mode. The primary entry points are:

*   `cl_scanfile`: This function is used to scan a file specified by its path. It handles opening, mapping, and scanning the file.
*   `cl_scandesc`: This function is used to scan a file specified by a file descriptor. This is useful when the file is already open or when scanning data from a stream.
*   `cl_scanmap_callback`: This function provides a more flexible way to scan data by using a callback mechanism. It allows the caller to provide data in chunks, which can be useful for scanning data from non-standard sources or for implementing custom scanning logic.

## The `cli_magic_scan` Function

The `cli_magic_scan` function plays a central role in the ClamAV scanning process. It is responsible for orchestrating the various stages of a scan, including:

*   **File type detection:** `cli_magic_scan` uses magic numbers and other heuristics to determine the type of the file being scanned.
*   **Preprocessing:** Based on the file type, `cli_magic_scan` may perform preprocessing steps, such as decompression or unpacking.
*   **Signature matching:** `cli_magic_scan` invokes the appropriate signature matching algorithms to detect known threats.
*   **Heuristic analysis:** `cli_magic_scan` may also perform heuristic analysis to detect new or unknown threats.
*   **Postprocessing:** After the scan is complete, `cli_magic_scan` may perform postprocessing steps, such as cleaning up temporary files or reporting the scan results.

## Scan Context (`cli_ctx`)

The scan context structure, `cli_ctx`, is a critical data structure that holds all the information related to a scan. This includes:

*   **Scan options:** The `cli_ctx` structure stores the scan options specified by the caller, such as the maximum file size to scan or the types of threats to detect.
*   **Engine state:** The `cli_ctx` structure maintains the current state of the ClamAV engine, including the loaded signature databases and any cached data.
*   **Scan results:** The `cli_ctx` structure stores the results of the scan, such as the names of any detected threats and the actions taken.

The `cli_ctx` structure is passed to most of the functions involved in the scanning process, allowing them to access and modify the scan context as needed.

## File Mapping (`fmap_t`)

File mapping is a technique used by ClamAV to efficiently access file data during a scan. The `fmap_t` structure represents a mapped file and provides a convenient way to access its contents as a contiguous block of memory.

By mapping a file into memory, ClamAV can avoid the overhead of repeated read operations and can access file data more quickly. This is particularly important for large files or when scanning files with complex formats.

The `fmap_t` structure stores information about the mapped file, such as its size, its starting address in memory, and the current read offset. It also provides functions for reading data from the mapped file and for unmapping the file when the scan is complete.

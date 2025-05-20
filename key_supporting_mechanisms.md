# Key Supporting Mechanisms

This document outlines several key supporting mechanisms within ClamAV that are crucial for managing the scan process, interacting with external components, optimizing performance, and ensuring stability.

## Recursion Management

ClamAV frequently encounters nested data structures, such as archives containing other archives, or documents with embedded objects. To manage these scenarios, a recursion management system is employed:

*   **`recursion_stack`**: This stack, typically part of the scan context (`cli_ctx`) and managed in `scanners.c`, keeps track of the current depth and state of nested scans.
*   Each time ClamAV decides to scan an embedded object or a file within an archive, it pushes a new level onto the `recursion_stack`. When the scan of that inner object completes, the level is popped.
*   This mechanism is essential for preventing infinite loops (e.g., a maliciously crafted archive that contains itself) and for enforcing recursion depth limits.

## Callbacks for External Interaction

ClamAV provides several callback points that allow external applications or custom code to interact with and respond to events during the scan process. These callbacks are often function pointers within structures like `cl_engine` or `cli_ctx`. Examples include:

*   **`cb_pre_scan`**: Called before a file or data stream is scanned.
*   **`cb_post_scan`**: Called after a file or data stream has been scanned, providing the scan result.
*   **`cb_virus_found`**: Called when a virus or threat is detected.
*   **`cb_file_inspection`**: Called to provide access to file content for inspection, potentially allowing the caller to make decisions or log information.

These callbacks enable flexible integration of ClamAV into larger systems and allow for customized handling of scan events.

## Scan Result Caching

To improve performance and avoid redundant scanning of known clean files, ClamAV implements a scan result caching mechanism.

*   When a file is scanned and found to be clean, information about this file (e.g., its hash and metadata) can be added to a cache.
*   **`clean_cache_check`**: Before scanning a new file, ClamAV can check this cache. If the file is found in the cache and has not been modified, the scan can be skipped.
*   **`clean_cache_add`**: If a file is scanned and found clean, it's added to the cache for future reference.
*   This mechanism significantly speeds up scans in environments where the same clean files are encountered repeatedly, such as during on-access scanning or repeated full system scans.

## Temporary File Management

During the analysis of complex files, especially archives or documents with embedded objects, ClamAV often needs to extract these components to temporary files on disk for individual scanning.

*   **`ctx->sub_tmpdir`**: The scan context (`cli_ctx`) often holds a reference to a subdirectory (`sub_tmpdir`) specifically created for storing these temporary files related to the current scan operation.
*   Functions like **`cli_gentemp`** are used to create unique temporary filenames within this directory.
*   Proper management of these temporary files is crucial for security (ensuring files are not accessible by other users) and for cleanup (ensuring temporary files are deleted after the scan is complete to free up disk space).

## Scan Limits

To protect against resource exhaustion (e.g., due to maliciously crafted files designed to cause excessive processing) and potential denial-of-service attacks, ClamAV enforces various scan limits. These limits are typically configurable and stored in structures like `cl_engine` or `cli_ctx`. Key examples include:

*   **`max_recursion_level`**: The maximum depth of nested scans (e.g., how many levels deep ClamAV will go into archives within archives).
*   **`maxfilesize`**: The maximum size of a single file that ClamAV will attempt to scan. Files larger than this limit may be skipped or truncated.
*   **`maxscansize`**: The maximum amount of data that will be scanned from any single file. This is useful for very large files where scanning the entire content might be too slow.
*   **`maxscantime`**: The maximum time allowed for scanning a single file. This prevents a single problematic file from monopolizing scan resources.

These limits ensure that ClamAV operates within predictable bounds, maintaining system stability and performance.

# Pattern Matching Engine

This document describes the pattern matching engine within ClamAV. This engine is responsible for searching for known malicious patterns (signatures) within files and data streams.

## `cli_scan_fmap`: The Central Matching Function

The function `cli_scan_fmap`, located in `matcher.c`, is a key component of the pattern matching process. It takes a memory-mapped file (`fmap_t`) as input, along with the scan context, and applies the various matching techniques to identify threats. This function acts as an entry point to the core matching logic, preparing the data and invoking deeper matching routines.

## `matcher_run`: Orchestrating Matching Algorithms

Internally, `cli_scan_fmap` often delegates the complex task of matching to the `matcher_run` function. `matcher_run` plays a crucial role in:

*   **Applying Filters:** It may apply pre-filtering logic to quickly rule out sections of data or to select specific matching algorithms based on the file type or scan context.
*   **Orchestrating Algorithms:** It coordinates the execution of different pattern matching algorithms, ensuring that the data is passed to each relevant algorithm in an efficient manner.
*   **Aggregating Results:** It gathers results from the various matching algorithms and determines if a conclusive threat detection has been made.

## Core Pattern Matching Algorithms

ClamAV employs a suite of pattern matching algorithms, each suited for different types of signatures and performance characteristics.

### Aho-Corasick

The Aho-Corasick algorithm is used extensively in ClamAV for its ability to match a large set of patterns (strings) simultaneously and efficiently. It preprocesses a dictionary of signatures into a finite state machine (automaton). During a scan, the input data is fed through this automaton, and any occurrences of the dictionary's patterns are reported. This is particularly effective for matching numerous simple byte sequences.

### Boyer-Moore

Boyer-Moore is another string searching algorithm known for its efficiency, especially when the patterns are relatively long. It preprocesses the pattern to create heuristic tables that allow it to skip sections of the text, leading to faster searches compared to naive string matching. ClamAV likely uses Boyer-Moore for specific types of signatures where its performance characteristics are advantageous.

### PCRE (Perl Compatible Regular Expressions)

For more complex patterns that cannot be expressed by simple byte sequences, ClamAV integrates support for Perl Compatible Regular Expressions (PCRE). PCRE provides a powerful and flexible way to define patterns using a rich syntax. This allows for the creation of signatures that can match variable content, specific sequences with wildcards, and other complex conditions. However, PCRE matching is generally more computationally intensive than Aho-Corasick or Boyer-Moore.

## Hash-Based Signatures

ClamAV supports hash-based signatures, often stored in `.hdb` (Hash Database) files. These signatures consist of hashes (e.g., MD5, SHA1, SHA256) of malicious files or parts of files.

During a scan, the engine calculates hashes of the input data (or specific sections identified by other means) and compares them against the hashes in its database. A match indicates that the scanned content is identical to known malware. This is a very fast and effective way to detect exact matches of known threats.

## Logical Signatures and `cli_exp_eval`

ClamAV allows for the creation of logical signatures, which define a threat based on a combination of multiple conditions or sub-signatures. These conditions are expressed as a logical expression (e.g., "sub-signature A AND sub-signature B OR sub-signature C").

The function `cli_exp_eval` (or a similar mechanism) is responsible for evaluating these logical expressions. After the individual sub-signatures are checked, `cli_exp_eval` determines if the overall logical condition defined by the signature is met. This enables the detection of more complex threats that might not be identifiable by a single, simple pattern.

## Yara Rule Integration

ClamAV integrates the Yara detection engine, allowing it to leverage Yara rules for malware identification. Yara is a powerful tool designed to help malware researchers identify and classify malware samples. Yara rules are descriptive and can be based on textual or binary patterns, regular expressions, and other characteristics.

The integration involves:
*   Loading and compiling Yara rules.
*   Running the Yara engine against the scanned data.
*   Translating Yara match results into ClamAV detection events.

This significantly extends ClamAV's detection capabilities by incorporating the flexibility and expressiveness of the Yara rule language.

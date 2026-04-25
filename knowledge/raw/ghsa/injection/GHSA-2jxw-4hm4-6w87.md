# SQL injection in llama-index

**GHSA**: GHSA-2jxw-4hm4-6w87 | **CVE**: CVE-2024-23751 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **llama-index** (pip): <= 0.9.35

## Description

LlamaIndex (aka llama_index) through 0.9.35 allows SQL injection via the Text-to-SQL feature in NLSQLTableQueryEngine, SQLTableRetrieverQueryEngine, NLSQLRetriever, RetrieverQueryEngine, and PGVectorSQLQueryEngine. For example, an attacker might be able to delete this year's student records via "Drop the Students table" within English language input.

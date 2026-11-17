-- The CVSS rating behind an advisory, as JSON: {"score":9.8,"version":"3.1","vector":"CVSS:3.1/...","source":"OSV severity"}.
-- Written by advisoryRow from the OSV record's own vector (scored by the CVSS library, never invented). NULL for malware,
-- for an advisory with no valid vector, and for every row written before this migration (a refresh fills it as records
-- are modified). Display and triage only: the KV index and the block decision do not read it. `severity` stays as the
-- categorical fallback.
ALTER TABLE advisories ADD COLUMN cvss_json TEXT;

# Metrics log excerpts
`rotation-1.log` and `rotation-2.log` contain anonymized production-log excerpts: four schema-1 snapshots and two helper-exit records. They cover a periodic/shutdown pair and the startup/first-periodic pair of its replacement process.

Counters, gauges, limits, histograms, sequence numbers, uptime and record order are preserved. Calendar dates are shifted; PIDs and monotonic instance identifiers are replaced consistently. Access records use documentation-only addresses and example names. No real address, domain, username or local filesystem path is retained. Original-source fingerprints and extraction records are kept in the untracked fixture provenance archive.

The file boundary splits a snapshot between complete physical records. Tests derive compressed rotations, corruption, missing/duplicate rows, PID reuse and startup-version records from these fixtures. Records without matching startup-version evidence must remain unknown.

`traffic.log` is an independent consecutive snapshot pair around a game connection with nonzero accepted/worker counter deltas. It must not be concatenated with the rotation pair without expecting sequence gaps.

# LANE REPORT — EG2 goldenct (GOLDEN-CONTRACT-PUSHABSORB-0001 quant closeout)
- Branch: wt/goldenct @ 27cd5a65 (base bf3f5064); zero src/ changes, write domain respected
- Baselines reproduced on fresh bare-mode E2E: curl 2561/0/0, httpd 2333/0/0
- Three-way (triple-matched skeleton lines): curl N=117 Rc=2557 Rd=4313 B=4386; httpd N=467 Rc=25327 Rd=36984 B=35367
- Consensus: C=D!=R (true library defect dir) = 63 (curl) / 4661 (httpd); pure-bridge fns 1/117 & 0/467
- Push verdict: DP upheld (direct keeps push prints; family 11.6%/13.1% of bridge gap)
- Verdict: dual-baseline layered gate (canonical = regression gate; direct-runner = library-truth dashboard)
- Forensics: predecessor outputs were stale-binary (curl 4091 anomaly, httpd truncated at 225 + orphan commit 5e93d30b numbers) — superseded by e285264b/27cd5a65
- Open items for root: httpd full-corpus 2 empty-else defects (ap_parse_uri L16, ap_invoke_handler L57); pcre_exec panic varnode.rs:2565; ap_build_cont_config/ap_log_rerror type-prop non-settling

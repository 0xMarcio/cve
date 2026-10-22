# Public PoC archives

The archive queue covers CVE-2026 and later, including new years automatically.
It uses the durable release ledger so removing an unavailable original does not
forget the opportunity to recover an older snapshot. Blacklisted repositories
and excluded CVE/repository associations stay excluded.

`Archive Public PoCs` is explicitly dispatched after hourly discovery, with a
six-hour recovery schedule and manual dispatch. Each run spends up to ten minutes
discovering source files in 100 repositories and ten minutes looking for existing
captures across 500 page URLs. It then takes up to 100 capture targets and resumes
pending captures within a 35-minute budget. New discoveries, old unprocessed
URLs, and source files each receive a share of the queue; attempted failures
cannot continually displace unseen entries.
The same queue drains the initial backfill and handles future discoveries.
Manual dispatch also offers 3- or 10-target batches and a five-minute budget for
checking credentials, captures and checkpoint recovery before a regular run.

- One workflow at a time owns captures. Do not run a local capture worker while
  that workflow is active.
- Submissions are spaced at least 15 seconds apart, with at most two pending
  captures and one API request per second. Account capacity and daily quotas are
  checked before a batch. Each URL is limited to two submissions per day.
  HTTP throttling, `Retry-After`, and account quota errors pause the queue;
  target failures only defer their URL or host. Cooldowns survive the next run.
- Pending job IDs, attempts, retry dates and verified captures are checkpointed
  in `index/archives/`. A separate publishing job merges results into current main
  under the existing repository update lock. Capture requests do not hold that
  lock. The next worker automatically recovers the latest checkpoint artifact
  if publishing failed; artifacts are retained for 14 days.
- Existing captures are looked up for live and unavailable pages before saving.
  Save Page Now reuses page captures from the last 30 days and immutable source
  captures regardless of age. Expired jobs also use the availability API.
  The lookup lane permits four outstanding reads, paced at one API request per
  second. Connection failures defer their target, not the entire backfill.
  A successful API
  response alone is insufficient: replay must return content, rather than a
  login/error page. The first verified snapshot is retained across refreshes.
  Captures must match the original URL and known publication window; GitHub
  repository identity and known source-file hashes are checked where available.
- `/archives.json` contains only verified links. The UI distinguishes a dated
  snapshot from an unverified history search. Confirmed dead original links can
  be replaced by a verified archive without resurrecting the dead link.

The account uses Internet Archive API keys, not paid Amazon S3 storage. Configure
`IA_ACCESS_KEY` and `IA_SECRET_KEY` as repository secrets. For a local run the same
environment variables work, or a private mode-0600
`~/.config/pocindex/internet-archive.json` containing `access` and `secret`.
Never commit credentials.

```sh
python3 scripts/archive_pocs.py --stats
python3 scripts/archive_sources.py --limit 100 --requests 800 --max-seconds 600
python3 scripts/archive_pocs.py --lookup-pages --limit 500 --max-seconds 600
python3 scripts/archive_pocs.py --capture --min-year 2026 --limit 100 --max-seconds 2100
```

Existing snapshots reduce capture work. Throttling, slow replays, blocked hosts
and retries affect throughput, so workflow summaries report actual progress
rather than an estimated completion promise.

## Preservation limits

A page snapshot is not a complete repository backup. The queue additionally
captures raw source files at immutable Git revisions. Source discovery scans
already published repositories independently of release-history enrichment,
verifies source bytes against Git blob hashes, and checkpoints partial scans.
Explicit file links also preserve formats such as Nuclei YAML. Issues and reports
do not cause unrelated files from their hosting repository to be copied.
It does not crawl arbitrary outbound links or claim to
save every repository file, attachment or dependency. Dynamic/login-only reports
may not be capturable. A missing snapshot remains visibly unconfirmed, and
Internet Archive can later remove or restrict access to a capture.

API references: [Wayback availability](https://archive.org/help/wayback_api.php),
[Save Page Now](https://help.archive.org/help/save-pages-in-the-wayback-machine/),
[Save Page Now API](https://docs.google.com/document/d/1Nsv52MvSjbLb2PCpHlat0gkzw0EvtSgpKHu4mk0MnrA/edit).

# Using the `IOCs/csv/*.csv` files in CQL hunts

**Platform:** CrowdStrike Falcon (CQL / LogScale / Next-Gen SIEM)

This guide shows how to feed the [`IOCs/csv/`](../IOCs/csv/) files into LogScale hunts without pasting hundreds of values into a regex by hand.

---

## Can CQL fetch the raw GitHub `.txt` files at query time? — **No.**

KQL has [`externaldata`](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator), which reaches out to any HTTPS URL on every query execution. **LogScale has no equivalent.** The query language can only read files that are already inside your tenant via:

- [`match()`](https://library.humio.com/data-analysis/functions-match.html) — lookup against an uploaded file (the workhorse)
- [`readFile()`](https://library.humio.com/data-analysis/functions-readfile.html) — read a file as a data source

Neither operator accepts a URL. There is no inline HTTP fetcher in CQL.

### What you can do instead — automate the upload

LogScale exposes a [**Files API**](https://library.humio.com/logscale-api/api-lookup.html) (cloud and self-hosted) that lets you `POST` a CSV and have it replace an existing lookup of the same name. Combine that with a GitHub Action triggered on commits to `IOCs/csv/**` and you get the same end-state as `externaldata`:

```text
git push  →  GitHub Action  →  LogScale Files API  →  match() picks up new IOCs on next run
```

The [GitHub Actions workflow at the bottom](#github-actions--auto-refresh) of this guide does exactly that.

---

## The eight CSV files

All eight live in [`IOCs/csv/`](../IOCs/csv/), each with a one-column header so LogScale auto-detects the schema. The `.txt` originals in [`IOCs/`](../IOCs/) are still maintained for human-readable diffs and KQL `externaldata`.

| CSV | Column | Rows | LogScale event | LogScale field |
| :--- | :--- | ---: | :--- | :--- |
| `code-signing.csv` | `signer` | 45 | `Event_ModuleSummaryInfoEvent` | `SubjectCN` |
| `chrome-extensions.csv` | `extension_id` | 112 | `DirectoryCreate` (also `RegSystemConfigValueUpdate`, `HttpRequest` for force-install / CRX download paths) | `FileName` directly (also extracted from `RegStringValue` / `HttpUrl` via regex) |
| `domains.csv` | `domain` | 133 | `DnsRequest`, `HttpRequest` | `DomainName`, `HttpHost` |
| `c2.csv` | `domain` | 17 | `DnsRequest`, `HttpRequest` | `DomainName`, `HttpHost` |
| `ips.csv` | `ip` | 13 | `NetworkConnectIP4` / `IP6` | `RemoteAddressIP4` / `IP6` |
| `hashes-sha256.csv` | `sha256` | 131 | `ProcessRollup2` | `SHA256HashData` |
| `hashes-sha1.csv` | `sha1` | 32 | `ProcessRollup2` | `SHA1HashData` |
| `hashes-md5.csv` | `md5` | 1 | `ProcessRollup2` | `MD5HashData` |

Hashes are split by length so each CSV maps cleanly to a single Falcon field — `match()` has no single-column-against-three-fields shorthand, and splitting beats an `OR` across `SHA256HashData / SHA1HashData / MD5HashData`.

---

## Step 1 — Upload via Falcon Console (one-time, manual path)

1. Falcon Console → **Next-Gen SIEM** → **Lookup files** → **Create file** → **Import file**
2. Pick each `.csv` from `IOCs/csv/`, set the **Repository** scope (or **Shared** if you want it visible across every repo)
3. Save with the same filename — LogScale auto-detects the header column

---

## Step 2 — Use `match()` in your queries

`match()` filters events down to those where a field's value appears in the named column of the named lookup file. Drop-in replacement for any inline regex / `in()` list.

### Code-signing — block-list of bad publishers

```java
#event_simpleName=Event_ModuleSummaryInfoEvent
| SubjectCN=*
| match(file="code-signing.csv", column="signer", field=SubjectCN, strict=true, ignoreCase=true)
| table([@timestamp, ComputerName, aid, SubjectCN, IssuerCN, SHA256HashData, FileName])
| sort(@timestamp, order=desc)
```

### Code-signing → execution pivot (one-shot join)

```java
#event_simpleName=ProcessRollup2
| join(
    query={
      #event_simpleName=Event_ModuleSummaryInfoEvent
      | SubjectCN=*
      | match(file="code-signing.csv", column="signer", field=SubjectCN, strict=true, ignoreCase=true)
      | groupBy([SHA256HashData], function=[selectLast(SubjectCN), selectLast(IssuerCN)])
    },
    field=SHA256HashData,
    include=[SubjectCN, IssuerCN],
    mode=inner
  )
| table([@timestamp, ComputerName, UserName, FileName, ImageFileName, CommandLine, SubjectCN, IssuerCN, SHA256HashData])
| sort(@timestamp, order=desc)
```

### Chrome extensions — bad-ID extension folder created

```java
#event_simpleName=DirectoryCreate 
| FilePath=/(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Chromium|Vivaldi|Opera\sSoftware|Yandex)\\/
| FilePath=/(?i)\\Extensions\\?$/i
| FileName=/^[a-p]{32}$/
| match(file="chrome-extensions.csv", column="extension_id", field=FileName, strict=true)
| groupBy([FileName, ComputerName],
          function=[min(@timestamp, as=FirstSeen),
                    max(@timestamp, as=LastSeen),
                    collect([FilePath, UserName])])
| sort(FirstSeen, order=asc)
```

### Lure domains — DNS / HTTP lookups against the PDF-tool cluster

```java
#event_simpleName=/^(DnsRequest|HttpRequest)$/ 
| DomainName=*
| match(file="domains.csv", column="domain", field=DomainName, strict=true, ignoreCase=true)
| table([@timestamp, ComputerName, UserName, DomainName, ContextBaseFileName, ContextImageFileName])
| sort(@timestamp, order=desc)
```

### C2 domains — same shape, separate file so you can promote sooner

```java
#event_simpleName=/^(DnsRequest|HttpRequest)$/ 
| DomainName=*
| match(file="c2.csv", column="domain", field=DomainName, strict=true, ignoreCase=true)
| Severity := "HIGH"
| table([@timestamp, ComputerName, UserName, DomainName, Severity, ContextBaseFileName])
| sort(@timestamp, order=desc)
```

### IPs — outbound connections to known infrastructure

```java
#event_simpleName=NetworkConnectIP4 
| RemoteAddressIP4=*
| match(file="ips.csv", column="ip", field=RemoteAddressIP4, strict=true)
| table([@timestamp, ComputerName, UserName, RemoteAddressIP4, RemotePort, ContextBaseFileName, ContextImageFileName])
| sort(@timestamp, order=desc)
```

> Many entries in `ips.csv` are Cloudflare-fronted shared ranges (`104.21.x.x`, `172.67.x.x`). Expect false positives — pair with the domain or hash hits before promoting to alert.

### File hashes — execution of known bad PEs (three separate files)

```java
// SHA-256 — 131 entries
#event_simpleName=ProcessRollup2
| SHA256HashData=*
| match(file="hashes-sha256.csv", column="sha256", field=SHA256HashData, strict=true, ignoreCase=true)
| table([@timestamp, ComputerName, UserName, FileName, FilePath, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

```java
// SHA-1 — 32 entries
#event_simpleName=ProcessRollup2
| SHA1HashData=*
| match(file="hashes-sha1.csv", column="sha1", field=SHA1HashData, strict=true, ignoreCase=true)
| table([@timestamp, ComputerName, UserName, FileName, FilePath, CommandLine, SHA1HashData])
| sort(@timestamp, order=desc)
```

```java
// MD5 — 1 entry, included for completeness
#event_simpleName=ProcessRollup2
| MD5HashData=*
| match(file="hashes-md5.csv", column="md5", field=MD5HashData, strict=true, ignoreCase=true)
| table([@timestamp, ComputerName, UserName, FileName, FilePath, CommandLine, MD5HashData])
| sort(@timestamp, order=desc)
```

### Hash hit → signer enrichment (optional add-on)

```java
#event_simpleName=ProcessRollup2
| SHA256HashData=*
| match(file="hashes-sha256.csv", column="sha256", field=SHA256HashData, strict=true, ignoreCase=true)
| join(
    query={
      #event_simpleName=Event_ModuleSummaryInfoEvent
      | groupBy([SHA256HashData], function=[selectLast(SubjectCN), selectLast(IssuerCN)])
    },
    field=SHA256HashData,
    include=[SubjectCN, IssuerCN],
    mode=left
  )
| table([@timestamp, ComputerName, UserName, FileName, FilePath, CommandLine, SHA256HashData, SubjectCN, IssuerCN])
| sort(@timestamp, order=desc)
```

---

## Refreshing the lookup files

### Option A — manual replace

In Falcon Console → **Files**, click **Replace file** on the existing entry and pick the new CSV. All `match(file="…")` queries pick up the new entries on the next run — no query edits needed.

### Option B — `curl` one-shot (LogScale API)

Per the [Lookup API docs](https://library.humio.com/logscale-api/api-lookup.html), uploading a file with the same name replaces it:

```bash
LOGSCALE_URL="https://cloud.community.humio.com"   # your tenant URL
REPO="threat-hunting"                              # destination repository
TOKEN="<your_logscale_api_token>"                  # personal API token

for f in IOCs/csv/*.csv; do
  curl -sS -X POST "$LOGSCALE_URL/api/v1/repositories/$REPO/files" \
       -H "Authorization: Bearer $TOKEN" \
       -F "file=@$f" \
       && echo "  uploaded: $f"
done
```

For **shared** lookup files (visible across all repos), the endpoint is `/api/v1/uploadedfiles/shared` instead, and only root users can write.

### Option C — `falconpy` (Foundry LogScale)

If you live in the Falcon API ecosystem already, [`falconpy`](https://www.falconpy.io/Service-Collections/Foundry-LogScale.html) wraps the same endpoints via `CreateFileV1` / `UpdateFileV1`.

---

## GitHub Actions — auto-refresh

Drop this in `.github/workflows/sync-iocs.yml`. Every push to `main` that touches `IOCs/csv/**` syncs the changed files to LogScale.

```yaml
name: Sync IOC CSVs to LogScale

on:
  push:
    branches: [main]
    paths:
      - "IOCs/csv/**.csv"
  workflow_dispatch:        # allow manual full-sync from the Actions UI

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Upload IOC CSVs to LogScale (replace if exists)
        env:
          LOGSCALE_URL: ${{ secrets.LOGSCALE_URL }}      # e.g. https://cloud.community.humio.com
          LOGSCALE_REPO: ${{ secrets.LOGSCALE_REPO }}    # e.g. threat-hunting
          LOGSCALE_TOKEN: ${{ secrets.LOGSCALE_TOKEN }}  # personal API token
        run: |
          set -euo pipefail
          for f in IOCs/csv/*.csv; do
            echo "Uploading $f"
            http_code=$(curl -sS -o /tmp/resp.json -w "%{http_code}" \
              -X POST "$LOGSCALE_URL/api/v1/repositories/$LOGSCALE_REPO/files" \
              -H "Authorization: Bearer $LOGSCALE_TOKEN" \
              -F "file=@$f")
            if [ "$http_code" -ge 400 ]; then
              echo "  FAILED ($http_code):"
              cat /tmp/resp.json
              exit 1
            fi
            echo "  OK ($http_code)"
          done
```

**Required repo secrets:**

| Secret | Example | Notes |
| :--- | :--- | :--- |
| `LOGSCALE_URL` | `https://cloud.community.humio.com` | No trailing slash |
| `LOGSCALE_REPO` | `threat-hunting` | The repository the lookups live in |
| `LOGSCALE_TOKEN` | (personal API token) | Generate under Account → API Tokens. Use a service-account user, not your personal user. |

For **NG-SIEM** tenants (vs. standalone LogScale): use the same Files API — NG-SIEM's "Files" feature is the LogScale Lookup Files feature under the hood.

---

## Inline `in()` for ad-hoc hunts

When you just want to test something quickly without uploading, a one-liner converts any of the `IOCs/*.txt` files to `in()`-ready syntax:

```bash
grep -Ev '^\s*(#|$)' IOCs/code-signing.txt | sed 's/.*/"&"/' | paste -sd ',' -
```

Then wrap with `in()`:

```java
#event_simpleName=Event_ModuleSummaryInfoEvent
| SubjectCN=*
| in(field="SubjectCN",
     values=["ECHO INFINI SDN. BHD.","GLINT SOFTWARE SDN. BHD.","Summit Nexus Holdings LLC"],
     ignoreCase=true)
| table([@timestamp, ComputerName, aid, SubjectCN, IssuerCN, SHA256HashData, FileName])
```

> **Reminder: `in()` does NOT support wildcards in `values=[]`.** For prefix / substring matching, use `field=/regex/` instead.

---

## Cheat sheet — which CSV → which event → which field

| Lookup file | Column | LogScale event | LogScale field |
| :--- | :--- | :--- | :--- |
| `code-signing.csv` | `signer` | `Event_ModuleSummaryInfoEvent` | `SubjectCN` (issuer enrichment via `IssuerCN`) |
| `chrome-extensions.csv` | `extension_id` | `DirectoryCreate` (primary), `RegSystemConfigValueUpdate` / `RegGenericValueUpdate` (force-install policy), `HttpRequest` (CRX download) | `FileName` directly on `DirectoryCreate`; captured via regex from `RegStringValue` / `HttpUrl` on the others |
| `domains.csv` | `domain` | `DnsRequest`, `HttpRequest` | `DomainName`, `HttpHost` |
| `c2.csv` | `domain` | `DnsRequest`, `HttpRequest` | `DomainName`, `HttpHost` |
| `ips.csv` | `ip` | `NetworkConnectIP4`, `NetworkConnectIP6` | `RemoteAddressIP4`, `RemoteAddressIP6` |
| `hashes-sha256.csv` | `sha256` | `ProcessRollup2` (`*FileWritten`, `ClassifiedModuleLoad` also carry it) | `SHA256HashData` |
| `hashes-sha1.csv` | `sha1` | `ProcessRollup2` (same as above) | `SHA1HashData` |
| `hashes-md5.csv` | `md5` | `ProcessRollup2` (same as above) | `MD5HashData` |

---

## References

- [LogScale Lookup API](https://library.humio.com/logscale-api/api-lookup.html) — upload/replace/delete endpoints
- [Lookup Files concept](https://library.humio.com/data-analysis/repositories-files-ui.html) — UI walkthrough, sync behavior across cluster nodes
- [`match()` function](https://library.humio.com/data-analysis/functions-match.html) — query-side usage
- [`falconpy` Foundry LogScale](https://www.falconpy.io/Service-Collections/Foundry-LogScale.html) — Python SDK wrapping the same endpoints

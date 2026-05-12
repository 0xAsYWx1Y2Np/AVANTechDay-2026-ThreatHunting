# Malicious Extensions (KQL)

**MITRE ATT&CK:** [T1176](https://attack.mitre.org/techniques/T1176/) — Browser Extensions
**Tactic:** [TA0003](https://attack.mitre.org/tactics/TA0003/) — Persistence
**Related:** [T1539](https://attack.mitre.org/techniques/T1539/) — Steal Web Session Cookie, [T1528](https://attack.mitre.org/techniques/T1528/) — Steal Application Access Token
**Platform:** Microsoft Defender XDR (KQL)

---

## Hypothesis

Malicious Chrome (and Chromium-based) extensions land on disk under a deterministic path that contains the **32-character extension ID** (`[a-p]{32}`):

- `\Google\Chrome\User Data\<Profile>\Extensions\<id>\<version>\`
- `\Microsoft\Edge\User Data\<Profile>\Extensions\<id>\<version>\`
- Registry policy: `SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`

The extension ID is derived from the SHA-256 of the public key in the CRX — it is a forced telemetry artifact.

The canonical bad-ID list lives in [`IOCs/chrome-extensions.txt`](../IOCs/chrome-extensions.txt) (112 IDs) and [`IOCs/csv/chrome-extensions.csv`](../IOCs/csv/chrome-extensions.csv).

---

## Query 1 — Block-list hit (file telemetry, Chrome + Edge + Brave)

Detects `manifest.json` writes under the per-extension folder for any ID in the bad list.

```kql
let BadExtensionIds = dynamic([
    // --- Socket cloudapi.stream campaign (Apr 2026) ---
    "obifanppcpchlehkjipahhphbcbjekfa", "mdcfennpfgkngnibjbpnpaafcjnhcjno",
    "mmecpiobcdbjkaijljohghhpfgngpjmk", "bfoofgelpmalhcmedaaeogahlmbkopfd",
    "cbfhnceafaenchbefokkngcbnejached", "ogogpebnagniggbnkbpjioobomdbmdcj",
    "ldmnhdllijbchflpbmnlgndfnlgmkgif", "lnajjhohknhgemncbaomjjjpmpdigedg",
    "aecccajigpipkpioaidignbgbeekglkd", "akebbllmckjphjiojeioooidhnddnplj",
    "akifdnfipbeoonhoeabdicnlcdhghmpn", "akkkopcadaalekbdgpdikhdablkgjagd",
    "alkfljfjkpiccfgbeocbbjjladigcleg", "alllblhkgghelnejlggmmgjbkdabidie",
    "amkkjdjjgiiamenbopfpdmjcleecjjgg", "amnaljnjmgajgajelnplfmidgjgbjfhe",
    "bbjdlbemjklojnbifkgameepcafflmem", "bdnanfggeppmkfhkgmpojkhanoplkacc",
    "bgdkbjcdecedfoejdfgeafdodjgfohno", "bnchgibgpgmlickioneccggfobljmhjc",
    "bpljfbcejldmgeoodnogeefaihjdgbam", "cbnekafldflkmngbgmbnfmchjaelnhem",
    "cdpiopekjeonfjeocbfebemgocjciepp", "cehdkmmfadpplgchnbjgdngdcjmhlfcc",
    "cljengcehefhflhoahaambmkknjekjib", "clpgopiimdjcilllcjncdkoeikkkcfbi",
    "cmeoegkmpbpcoabhlklbamfeidebgmdf", "cmlbghnlnbjkdgfjlegkbjmadpbmlgjb",
    "cnibdhllkgidlgmaoanhkemjeklneolk", "cpnfioldnmhaihohppoaebillnambcgn",
    "dbohcpohlgnhgjmfkakoniiplglpfhcb", "dcamdpfclondppklabgkfaofjccpioil",
    "dljlpildgknddpnahppkihgodokfjbnd", "dlpiookhionidajbiopmaajeckifeehn",
    "dmaibhbbpmdihedidicfeigilkbobcog", "dohenclhhdfljpjlnpjnephpccbdgmmb",
    "dpdemambcedffmnkfmkephnhhnclmcio", "ejlcbfmhjbkgohopdkijfgggbikgbacb",
    "eljfpgehlncincemdmmnebmnlcmfamhm", "enmmilgindjmffoljaojkcgloakmloen",
    "eoklnfefipnjfeknpmigmogeeepddcch", "fddajeklkkggbnppabbhkdmnkdjindlo",
    "fibgndhgobbaaekmnneapojgkcehaeac", "fjfhejmbhpabkacpoddjbcfandjoacmb",
    "flkdjodmoefccepdihipjdlianmkmhgc", "fmajpchoiahphjiligpmghnhmabolhoh",
    "gaafhblhbnkekenogcjniofhbicchlke", "gbaoddbbpompjhmilbgiaapkkakldlpc",
    "gbhhgipmedccnankkjchgcidiigmioio", "gfhcdakcnpahfdealajmhcapnhhablbp",
    "gipmochingljoikdjakkdolfcbphmlom", "glofhphmolanicdaddgkmhfmjidjkaem",
    "haochenfmhglpholokliifmlpafilfdc", "hbobdcfpgonejphpemijgjddanoipbkj",
    "hdmppejcahhppjhkncagagopecddokpi", "heljkmdknlfhiecpknceodpbokeipigo",
    "hiofkndodabpioiheinoiojjobadpgmj", "hkbihmjhjmehlocilifheeaeiljabenb",
    "hlmdnedepbbihmbddepemmbkenbnoegd", "hmlnefhgicedcmebmkjdcogieefbaagl",
    "hnpbijogiiaegambgpaenjbcbgaeimlf", "ibelidmkbnjmmpjgfibbdbkamgcbnjdm",
    "ihbkmfoadnfjgkpdmgcboiehapkiflme", "ijccacgjefefdpglhclnbpfjlcbagafm",
    "ijfmkphjcogaealhjgijjfjlkpdhhojk", "ijpgccpmogehkjhdmomckpkfcpbjlmnj",
    "imjmnghlhiimodfkdkgnfplhlobehnpm", "jddinhnhplibccfmniaakhffpjpnaglp",
    "jmopjanoebpdbopigcbpjhiigmjolikk", "jnmmbmkmbkcccpihjgnhjmhhkokfdnfe",
    "jodocbbdcdclkhjkibnlfhbmllcpfkfo", "kahcolfecjbejjjadhjafmihdnifonjf",
    "kblomapfkjidbbbdllmofkcakcenkmec", "kbmindomjiejdikjaagfdbdfpnlanobi",
    "kbnkkecifeppobnemkielnpagifkobki", "kjnakdbpijigdbfepipnbafnhbcfdkga",
    "kknakidneabpfgepadgpkibalcnabnnh", "klglejfbdeipgklgaepnodpjcnhaihkd",
    "kmiidcaojgeepjlccoalkdimgpfnbagj", "lcijkepobdokkgmefebkiejhealgblle",
    "lefndgfmmbdklidbkeifpgclmpnhcilg", "lfkknbmaifjomagejflmjklcmpadmmdg",
    "ljbgkfbiifhpgpipepnfefijldolkhlm", "lmcpbhamfpbonaenickjclacodolkbdl",
    "lmgenhmehbcolpikplhkoelmagdhoojn", "maeccdadgnadblfddcmanhpofobhgfme",
    "medkneifmjcpgmmibfppjpfjbkgbgebl", "mheomooihiffmcgldolenemmplpgoahn",
    "mmbbjakjlpmndjlbhihlddgcdppblpka", "mmbkmjmlnhocfcnjmbchmflamalekbnb",
    "nbgligggjfgkpphhghhjdoiefbimgooc", "ncpdkpcgmdhhnmcjgiiifdhefmekdcnf",
    "ndajcmifndknmkckdcdefkpgcodciggk", "nelbpdjegmhhgpfcjclhdmkcglimkjpp",
    "nkacmelgoeejhjgmmgflbcdhonpaplcg", "nmegibgeklckejdlfhoadhhbgcdjnojb",
    "nodobilhjanebkafmpihkpoabiggnnfl", "oanpifaoclmgmflmddlgkikfaggejobn",
    "ocflhkadmmnlbieoiiekfcdcmjcfeahe", "odeccdcabdffpebnfancpkepjeecempn",
    "oejhnncfanbaogjlbknmlgjpleachclf", "ogbaedmbbmmipljceodeimlckohbnfan",
    "ojkbafekojdcedacileemekjdfdpkbkf", "pdgaknahllnfldmclpcllpieafkaibmf",
    "peflgkmfmoijonfgcjdlpnnfdegnlaji", "phfkdailnomcbcknpdmokejhellbecjb",
    "pkghgkfjhjghinikeanecbgjehojfhdg", "pllkanemicadpcmkfodglahcocfdgkhj",
    "fnmihdojmnkclgjpcoonokmkhjpjechg",
    // --- Unit 42 Chrome MCP Server RAT (Feb 2026) ---
    "fpeabamapgecnidibdmjoepaiehokgda",
    // --- Socket VKfeed (Feb 2026) ---
    "pcdgkgbadeggbnodegejccjffnoakcoh",
    // --- Socket CL Suite by @CLMasters (Feb 2026) ---
    "jkphinfhmfkckkcnifhjiplhfoiefffl"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath matches regex @"(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Chromium|Vivaldi|Opera Software|Yandex)\\User Data\\[^\\]+\\Extensions\\"
| extend ExtensionId = tostring(extract(@"\\Extensions\\([a-p]{32})\\", 1, FolderPath))
| where isnotempty(ExtensionId)
| where ExtensionId in (BadExtensionIds)
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          ExtensionId, FileName, FolderPath, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

## Query 1 — Block-list hit via `externaldata` (recommended)

```kql
let BadExtensionIds =
    externaldata(extension_id: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/chrome-extensions.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project extension_id = tolower(trim(@"\s+", extension_id))
    | summarize by extension_id;
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FolderCreated"
| where FolderPath matches regex @"(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Chromium|Vivaldi|Opera\sSoftware|Yandex)\\.*\\Extensions\\[a-p]{32}$"
| extend ExtensionId = tolower(extract(@"\\Extensions\\([a-p]{32})$", 1, FolderPath))
| where ExtensionId in (BadExtensionIds)
| summarize FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            DeviceCount = dcount(DeviceId),
            Devices = make_set(DeviceName, 20),
            Users = make_set(InitiatingProcessAccountName, 10),
            FolderSamples = make_set(FolderPath, 5)
    by ExtensionId
| sort by LastSeen desc
```

---

## Query 2 — Force-installed via Group Policy / MDM

```kql
let BadExtensionIds =
    externaldata(extension_id: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/chrome-extensions.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project extension_id = tolower(trim(@"\s+", extension_id))
    | summarize by extension_id;
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey matches regex @"(?i)\\SOFTWARE\\Policies\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave)\\ExtensionInstallForcelist"
// Policy value format: "<extid>;https://clients2.google.com/service/update2/crx"
| extend ExtensionId = tolower(extract(@"([a-p]{32})", 1, RegistryValueData))
| where isnotempty(ExtensionId) and ExtensionId in (BadExtensionIds)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          ExtensionId, RegistryKey, RegistryValueName, RegistryValueData
| sort by Timestamp desc
```

---

## Query 3 — Tenant-wide extension inventory (no bad-list)

The smartest detection in the pack. Surfaces every extension directory creation across the tenant with first / last seen and device count. Use to baseline, or to triage incidents where the actor's ID isn't in any public bad-list yet.

`DeviceCount < 5` for novelty detection — catches tomorrow's campaign before the bad-list updates.

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FolderCreated"
| where FolderPath matches regex @"(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Chromium|Vivaldi|Opera\sSoftware|Yandex)\\.*\\Extensions\\[a-p]{32}$"
| extend ExtensionId = tolower(extract(@"\\Extensions\\([a-p]{32})$", 1, FolderPath))
| summarize FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            InstallCount = count(),
            DeviceCount = dcount(DeviceId),
            Devices = make_set(DeviceName, 20)
    by ExtensionId
| where DeviceCount < 5    // novelty filter: low-spread extensions are higher signal
| sort by LastSeen desc
```

---

## Query 4 — CRX download from the Web Store

```kql
let BadExtensionIds =
    externaldata(extension_id: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/chrome-extensions.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project extension_id = tolower(trim(@"\s+", extension_id))
    | summarize by extension_id;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl matches regex @"(?i)(clients2\.google\.com/service/update2/crx|edge\.microsoft\.com/extensionwebstorebase/v1/crx)"
| extend ExtensionId = tolower(extract(@"(?:id%3D|id=)([a-p]{32})", 1, RemoteUrl))
| where isnotempty(ExtensionId) and ExtensionId in (BadExtensionIds)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          ExtensionId, RemoteUrl, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- Extension IDs are **deterministic** — derived from the SHA-256 of the public key in the CRX. They cannot be rotated without breaking the extension's update channel. This is the durable invariant.
- Sideloaded / unpacked extensions get a random ID and won't match a static bad-list. **Query 3** (inventory mode) is the answer for those — anomalous IDs on a tiny number of hosts.
- Chrome / Edge / Brave / Vivaldi / Opera / Yandex / Chromium all share the same `User Data\…\Extensions\<id>` layout — the regex covers all of them.
- For users running a **non-default Chrome profile** (`Profile 1`, `Profile 2`, …), the regex `.*` in the User Data segment handles every profile name.

## Coverage map

| Campaign | IDs | Source |
|---|---|---|
| Socket — cloudapi.stream MaaS | 109 | https://socket.dev/blog/108-chrome-ext-linked-to-data-exfil-session-theft-shared-c2 |
| Unit 42 — Chrome MCP Server RAT | 1 | https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-02-11-IOCs-for-RAT-disguinsed-as-AI-based-browser-extension.txt |
| Socket — VKfeed | 1 | https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html |
| Socket — CL Suite by @CLMasters | 1 | https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html |
| **Total** | **112** | |

## References

- [MITRE ATT&CK T1176](https://attack.mitre.org/techniques/T1176/)
- [DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- [DeviceRegistryEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table)
- [`externaldata` operator](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator)

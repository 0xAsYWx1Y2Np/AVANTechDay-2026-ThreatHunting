# Malicious Chrome Extensions (KQL)

**MITRE ATT&CK:** [T1176](https://attack.mitre.org/techniques/T1176/) — Browser Extensions
**Tactic:** [TA0003](https://attack.mitre.org/tactics/TA0003/) — Persistence
**Related:** [T1539](https://attack.mitre.org/techniques/T1539/) — Steal Web Session Cookie, [T1528](https://attack.mitre.org/techniques/T1528/) — Steal Application Access Token
**Platform:** Microsoft Defender XDR (KQL)

---

## Hypothesis

Malicious Chrome (and Chromium-based Edge / Brave) extensions land on disk under a deterministic path that contains the **32-character extension ID** (`[a-p]{32}`). Whether the extension was installed via Web Store, sideloaded as an unpacked folder, or force-installed via `ExtensionInstallForcelist` policy, the ID is a forced-telemetry artifact:

- `…\Google\Chrome\User Data\<Profile>\Extensions\<id>\<version>\`
- `…\Microsoft\Edge\User Data\<Profile>\Extensions\<id>\<version>\`
- `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist\*`
- `HKLM\SOFTWARE\(Wow6432Node\)?Google\Chrome\Extensions\<id>`

Combined with a curated bad-ID list, this is high-confidence and survives the bundle being repacked or renamed.

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

## Query 2 — Force-installed via Group Policy / MDM

Detects writes to the `ExtensionInstallForcelist` policy key — used both by legitimate admin pushes **and** by malware that survives reinstall by setting policy.

```kql
let BadExtensionIds = dynamic([
    "obifanppcpchlehkjipahhphbcbjekfa", "fpeabamapgecnidibdmjoepaiehokgda",
    "pcdgkgbadeggbnodegejccjffnoakcoh", "jkphinfhmfkckkcnifhjiplhfoiefffl"
    // Add full list from IOCs/chrome-extensions.txt as needed
]);
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has_any (
    @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
    @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist",
    @"SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist"
  )
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
// RegistryValueData = "<extension_id>;<update_url>"
| extend ExtensionId = tostring(extract(@"([a-p]{32})", 1, RegistryValueData))
| where isnotempty(ExtensionId)
| where ExtensionId in (BadExtensionIds) or RegistryValueData has "clients2.google.com/service/update2/crx"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          ExtensionId, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

## Query 3 — Tenant-wide extension inventory + bad-list join

A compact "did anyone install one of these" rollup. Useful for incident response or pre-deployment baselining.

```kql
let BadExtensionIds = externaldata(ExtensionId:string)
    // OPTIONAL: replace with a static dynamic([...]) list if you do not host the IOCs externally
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/extensions.txt"]
    with (format="txt", ignoreFirstRecord=false);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath matches regex @"(?i)\\User Data\\[^\\]+\\Extensions\\[a-p]{32}\\"
| extend ExtensionId = tostring(extract(@"\\Extensions\\([a-p]{32})\\", 1, FolderPath))
| where isnotempty(ExtensionId)
| join kind=inner (BadExtensionIds | where ExtensionId matches regex @"^[a-p]{32}$") on ExtensionId
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count()
    by DeviceName, AccountName=InitiatingProcessAccountName, ExtensionId
| sort by LastSeen desc
```

## Query 4 — CRX download from the Web Store

Picks up the actual `.crx` fetch from Google's update server. The extension ID is in the query string (`x=id%3D<id>%26…`).

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "clients2.google.com/service/update2/crx"
   or RemoteUrl has "edge.microsoft.com/extensionwebstorebase/v1/crx"
| extend ExtensionId = tostring(extract(@"(?:id%3D|id=)([a-p]{32})", 1, RemoteUrl))
| where isnotempty(ExtensionId)
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          ExtensionId, RemoteUrl, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- Extension IDs are **deterministic**: derived from the SHA-256 of the public key in the CRX. They cannot be changed without breaking the extension's update channel. This is the durable invariant.
- Sideloaded / unpacked extensions get a random ID and won't match a bad-list. For those, **Query 1** on the folder pattern (without the `where ExtensionId in (BadExtensionIds)` filter) surfaces all extension installs for tenant-wide inventory.
- Edge and Brave install Chrome Web Store extensions under their own `User Data` tree — Query 1 covers both.
- A Microsoft Defender Vulnerability Management browser-extension inventory feature also exists (`DeviceTvmBrowserExtensions`, `DeviceTvmBrowserExtensionsKB`, `DeviceTvmBrowserExtensionsPermissionsInfo`) — useful as a complementary signal but populated less frequently than the raw telemetry above.

## Coverage map

| Campaign | IDs | Source |
|---|---|---|
| Socket — cloudapi.stream MaaS | 108 | https://socket.dev/blog/108-chrome-ext-linked-to-data-exfil-session-theft-shared-c2 |
| Unit 42 — Chrome MCP Server RAT | 1 | https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-02-11-IOCs-for-RAT-disguinsed-as-AI-based-browser-extension.txt |
| Socket — VKfeed | 1 | https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html |
| Socket — CL Suite by @CLMasters | 1 | https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html |
| **Total** | **111** | |
# Malicious Chrome Extensions

**MITRE ATT&CK:** [T1176](https://attack.mitre.org/techniques/T1176/) — Browser Extensions
**Tactic:** [TA0003](https://attack.mitre.org/tactics/TA0003/) — Persistence
**Related:** [T1539](https://attack.mitre.org/techniques/T1539/) — Steal Web Session Cookie, [T1528](https://attack.mitre.org/techniques/T1528/) — Steal Application Access Token
**Platform:** CrowdStrike Falcon (CQL / LogScale)

---

## Hypothesis

Malicious Chrome (and Chromium-based Edge / Brave) extensions land on disk under a deterministic path that contains the **32-character extension ID** (`[a-p]{32}`). The extension ID is derived from the SHA-256 of the public key in the CRX — it is a forced telemetry artifact:

- Get all extensions from Chrome in your environment
- `\Google\Chrome\User Data\<Profile>\Extensions\<id>\<version>\`
- `\Microsoft\Edge\User Data\<Profile>\Extensions\<id>\<version>\`
- Registry policy: `SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`
- Web Store CRX download: `https://clients2.google.com/service/update2/crx?...x=id%3D<id>%26...`

Combined with a curated bad-ID list, this is high-confidence and survives bundle repacking or renaming.

---

## Query 1 - Get all extensions from Chrome in your environment

```java
#event_simpleName="DirectoryCreate" FilePath=/Chrome/i FilePath=/Extensions/i
| FileName=/^[a-p]{32}$/
| groupBy([FileName, ComputerName],
          function=[min(@timestamp, as=FirstSeen),
                    max(@timestamp, as=LastSeen),
                    collect([FilePath, UserName])])
| sort(FirstSeen, order=asc)
```

### Count the extensions from Chrome in your environment

```java
#event_simpleName="DirectoryCreate" FilePath=/Chrome/i FilePath=/Extensions/i
| groupBy([FileName])
| FileName=/^[a-p]{32}$/
```

---

## Query 2 — Block-list hit (file write to extension folder)

Detects writes (typically `manifest.json` first) under the per-extension folder for any ID in the bad list.

```java
TargetFileName=/(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Chromium|Vivaldi|Opera\sSoftware|Yandex)\\User\sData\\[^\\]+\\Extensions\\(?<ExtensionId>[a-p]{32})\\/
| ExtensionId=/^(obifanppcpchlehkjipahhphbcbjekfa|mdcfennpfgkngnibjbpnpaafcjnhcjno|mmecpiobcdbjkaijljohghhpfgngpjmk|bfoofgelpmalhcmedaaeogahlmbkopfd|cbfhnceafaenchbefokkngcbnejached|ogogpebnagniggbnkbpjioobomdbmdcj|ldmnhdllijbchflpbmnlgndfnlgmkgif|lnajjhohknhgemncbaomjjjpmpdigedg|aecccajigpipkpioaidignbgbeekglkd|akebbllmckjphjiojeioooidhnddnplj|akifdnfipbeoonhoeabdicnlcdhghmpn|akkkopcadaalekbdgpdikhdablkgjagd|alkfljfjkpiccfgbeocbbjjladigcleg|alllblhkgghelnejlggmmgjbkdabidie|amkkjdjjgiiamenbopfpdmjcleecjjgg|amnaljnjmgajgajelnplfmidgjgbjfhe|bbjdlbemjklojnbifkgameepcafflmem|bdnanfggeppmkfhkgmpojkhanoplkacc|bgdkbjcdecedfoejdfgeafdodjgfohno|bnchgibgpgmlickioneccggfobljmhjc|bpljfbcejldmgeoodnogeefaihjdgbam|cbnekafldflkmngbgmbnfmchjaelnhem|cdpiopekjeonfjeocbfebemgocjciepp|cehdkmmfadpplgchnbjgdngdcjmhlfcc|cljengcehefhflhoahaambmkknjekjib|clpgopiimdjcilllcjncdkoeikkkcfbi|cmeoegkmpbpcoabhlklbamfeidebgmdf|cmlbghnlnbjkdgfjlegkbjmadpbmlgjb|cnibdhllkgidlgmaoanhkemjeklneolk|cpnfioldnmhaihohppoaebillnambcgn|dbohcpohlgnhgjmfkakoniiplglpfhcb|dcamdpfclondppklabgkfaofjccpioil|dljlpildgknddpnahppkihgodokfjbnd|dlpiookhionidajbiopmaajeckifeehn|dmaibhbbpmdihedidicfeigilkbobcog|dohenclhhdfljpjlnpjnephpccbdgmmb|dpdemambcedffmnkfmkephnhhnclmcio|ejlcbfmhjbkgohopdkijfgggbikgbacb|eljfpgehlncincemdmmnebmnlcmfamhm|enmmilgindjmffoljaojkcgloakmloen|eoklnfefipnjfeknpmigmogeeepddcch|fddajeklkkggbnppabbhkdmnkdjindlo|fibgndhgobbaaekmnneapojgkcehaeac|fjfhejmbhpabkacpoddjbcfandjoacmb|flkdjodmoefccepdihipjdlianmkmhgc|fmajpchoiahphjiligpmghnhmabolhoh|gaafhblhbnkekenogcjniofhbicchlke|gbaoddbbpompjhmilbgiaapkkakldlpc|gbhhgipmedccnankkjchgcidiigmioio|gfhcdakcnpahfdealajmhcapnhhablbp|gipmochingljoikdjakkdolfcbphmlom|glofhphmolanicdaddgkmhfmjidjkaem|haochenfmhglpholokliifmlpafilfdc|hbobdcfpgonejphpemijgjddanoipbkj|hdmppejcahhppjhkncagagopecddokpi|heljkmdknlfhiecpknceodpbokeipigo|hiofkndodabpioiheinoiojjobadpgmj|hkbihmjhjmehlocilifheeaeiljabenb|hlmdnedepbbihmbddepemmbkenbnoegd|hmlnefhgicedcmebmkjdcogieefbaagl|hnpbijogiiaegambgpaenjbcbgaeimlf|ibelidmkbnjmmpjgfibbdbkamgcbnjdm|ihbkmfoadnfjgkpdmgcboiehapkiflme|ijccacgjefefdpglhclnbpfjlcbagafm|ijfmkphjcogaealhjgijjfjlkpdhhojk|ijpgccpmogehkjhdmomckpkfcpbjlmnj|imjmnghlhiimodfkdkgnfplhlobehnpm|jddinhnhplibccfmniaakhffpjpnaglp|jmopjanoebpdbopigcbpjhiigmjolikk|jnmmbmkmbkcccpihjgnhjmhhkokfdnfe|jodocbbdcdclkhjkibnlfhbmllcpfkfo|kahcolfecjbejjjadhjafmihdnifonjf|kblomapfkjidbbbdllmofkcakcenkmec|kbmindomjiejdikjaagfdbdfpnlanobi|kbnkkecifeppobnemkielnpagifkobki|kjnakdbpijigdbfepipnbafnhbcfdkga|kknakidneabpfgepadgpkibalcnabnnh|klglejfbdeipgklgaepnodpjcnhaihkd|kmiidcaojgeepjlccoalkdimgpfnbagj|lcijkepobdokkgmefebkiejhealgblle|lefndgfmmbdklidbkeifpgclmpnhcilg|lfkknbmaifjomagejflmjklcmpadmmdg|ljbgkfbiifhpgpipepnfefijldolkhlm|lmcpbhamfpbonaenickjclacodolkbdl|lmgenhmehbcolpikplhkoelmagdhoojn|maeccdadgnadblfddcmanhpofobhgfme|medkneifmjcpgmmibfppjpfjbkgbgebl|mheomooihiffmcgldolenemmplpgoahn|mmbbjakjlpmndjlbhihlddgcdppblpka|mmbkmjmlnhocfcnjmbchmflamalekbnb|nbgligggjfgkpphhghhjdoiefbimgooc|ncpdkpcgmdhhnmcjgiiifdhefmekdcnf|ndajcmifndknmkckdcdefkpgcodciggk|nelbpdjegmhhgpfcjclhdmkcglimkjpp|nkacmelgoeejhjgmmgflbcdhonpaplcg|nmegibgeklckejdlfhoadhhbgcdjnojb|nodobilhjanebkafmpihkpoabiggnnfl|oanpifaoclmgmflmddlgkikfaggejobn|ocflhkadmmnlbieoiiekfcdcmjcfeahe|odeccdcabdffpebnfancpkepjeecempn|oejhnncfanbaogjlbknmlgjpleachclf|ogbaedmbbmmipljceodeimlckohbnfan|ojkbafekojdcedacileemekjdfdpkbkf|pdgaknahllnfldmclpcllpieafkaibmf|peflgkmfmoijonfgcjdlpnnfdegnlaji|phfkdailnomcbcknpdmokejhellbecjb|pkghgkfjhjghinikeanecbgjehojfhdg|pllkanemicadpcmkfodglahcocfdgkhj|fpeabamapgecnidibdmjoepaiehokgda|fnmihdojmnkclgjpcoonokmkhjpjechg|pcdgkgbadeggbnodegejccjffnoakcoh|jkphinfhmfkckkcnifhjiplhfoiefffl)$/
| groupBy([aid, ComputerName, UserName, ExtensionId],
          function=[count(as=WriteCount), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen), collect(TargetFileName)])
| sort(LastSeen, order=desc)
```

---

## Query 3 — Force-installed via Group Policy / MDM

Hits writes to the `ExtensionInstallForcelist` policy key — used by legitimate admin pushes **and** by malware persisting via policy. Combine with the bad-list to focus on the latter.

```java
#event_simpleName=/^(RegSystemConfigValueUpdate|RegGenericValueUpdate)$/ event_platform=Win
| RegObjectName=/(?i)\\SOFTWARE\\Policies\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave)\\ExtensionInstallForcelist/
| regex("(?<ExtensionId>[a-p]{32})", field=RegStringValue, strict=false)
| ExtensionId=/^(obifanppcpchlehkjipahhphbcbjekfa|fpeabamapgecnidibdmjoepaiehokgda|pcdgkgbadeggbnodegejccjffnoakcoh|jkphinfhmfkckkcnifhjiplhfoiefffl)$/
| table([@timestamp, ComputerName, UserName, ExtensionId, RegObjectName, RegStringValue])
| sort(@timestamp, order=desc)
```

---

## Query 4 — Tenant-wide extension inventory (no bad-list)

Surfaces every extension folder write seen across the tenant, with first/last seen and host count. Use as a baseline or to triage incidents where the actor's ID isn't in any public bad-list yet.

```java
#event_simpleName=/^(PeFileWritten|NewExecutableWritten|FileWritten|NewScriptWritten)$/ event_platform=Win
| TargetFileName=/(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Chromium|Vivaldi|Opera\sSoftware|Yandex)\\User\sData\\[^\\]+\\Extensions\\(?<ExtensionId>[a-p]{32})\\/
| groupBy([ExtensionId],
          function=[
            count(as=WriteCount),
            count(field=aid, distinct=true, as=HostCount),
            min(@timestamp, as=FirstSeen),
            max(@timestamp, as=LastSeen),
            collect(fields=[ComputerName], limit=20, separator=", ")
          ])
| Hosts := ComputerName
| HostCount < 5
| sort(LastSeen, order=desc)
```

---

## Query 5 — CRX download from the Web Store

Catches the actual `.crx` fetch from Google's update server. The extension ID is in the query string (`x=id%3D<id>%26...`).

```java
#event_simpleName=/^(DnsRequest|HttpRequest)$/
| DomainName=/(?i)^(clients2\.google\.com|edge\.microsoft\.com)$/
   OR HttpUrl=/(?i)(clients2\.google\.com\/service\/update2\/crx|edge\.microsoft\.com\/extensionwebstorebase\/v1\/crx)/
| regex("(?:id%3D|id=)(?<ExtensionId>[a-p]{32})", field=HttpUrl, strict=false)
| ExtensionId=/^(obifanppcpchlehkjipahhphbcbjekfa|fpeabamapgecnidibdmjoepaiehokgda|pcdgkgbadeggbnodegejccjffnoakcoh|jkphinfhmfkckkcnifhjiplhfoiefffl)$/
| table([@timestamp, ComputerName, UserName, ExtensionId, HttpUrl])
| sort(@timestamp, order=desc)
```

---

## Notes

- Extension IDs are **deterministic** — derived from the SHA-256 of the public key in the CRX. They cannot be rotated without breaking the extension's update channel. This is the durable invariant.
- Sideloaded / unpacked extensions get a random ID and won't match a static bad-list. **Query 3** (inventory mode) is the answer for those — anomalous IDs on a tiny number of hosts.
- Chrome / Edge / Brave / Vivaldi / Opera / Yandex / Chromium all share the same `User Data\…\Extensions\<id>` layout — the regex covers all of them.
- For users running a **non-default Chrome profile** (`Profile 1`, `Profile 2`, …), the regex `[^\\]+` in the `User Data` segment handles every profile name.
- The Web Store CRX URL pattern is stable, but Chrome also supports **`update_url=`** in `ExtensionInstallForcelist` — adversaries occasionally host their own update servers. Query 2 surfaces those via the policy write itself, even if the CRX URL is unfamiliar.

## Coverage map

| Campaign | IDs | Source |
|---|---|---|
| Socket — cloudapi.stream MaaS | 108 | https://socket.dev/blog/108-chrome-ext-linked-to-data-exfil-session-theft-shared-c2 |
| Unit 42 — Chrome MCP Server RAT | 1 | https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-02-11-IOCs-for-RAT-disguinsed-as-AI-based-browser-extension.txt |
| Socket — VKfeed | 1 | https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html |
| Socket — CL Suite by @CLMasters | 1 | https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html |
| **Total** | **111** | |
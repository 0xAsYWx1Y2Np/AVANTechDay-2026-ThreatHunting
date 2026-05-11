# Malicious Chrome Extensions

**MITRE ATT&CK:** [T1176](https://attack.mitre.org/techniques/T1176/) — Browser Extensions
**Tactic:** [TA0003](https://attack.mitre.org/tactics/TA0003/) — Persistence
**Related:** [T1539](https://attack.mitre.org/techniques/T1539/) — Steal Web Session Cookie, [T1528](https://attack.mitre.org/techniques/T1528/) — Steal Application Access Token
**Platform:** CrowdStrike Falcon (CQL / LogScale)

---

## Hypothesis

Malicious Chrome (and Chromium-based Edge / Brave) extensions land on disk under a deterministic path that contains the **32-character extension ID** (`[a-p]{32}`). The extension ID is derived from the SHA-256 of the public key in the CRX — it is a forced telemetry artifact:

- `\Google\Chrome\User Data\<Profile>\Extensions\<id>\<version>\`
- `\Microsoft\Edge\User Data\<Profile>\Extensions\<id>\<version>\`
- Registry policy: `SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`

Combined with a curated bad-ID list, this is high-confidence and survives bundle repacking or renaming.

> **To consume the bad-ID list directly from [`IOCs/chrome-extensions.txt`](../IOCs/chrome-extensions.txt)** (instead of pasting the IDs into the regex), see [`UsingIOCFiles.md`](UsingIOCFiles.md).

---

## Regex search

Use this query to search over all events and fields.

```java
/obifanppcpchlehkjipahhphbcbjekfa|mdcfennpfgkngnibjbpnpaafcjnhcjno|mmecpiobcdbjkaijljohghhpfgngpjmk|bfoofgelpmalhcmedaaeogahlmbkopfd|cbfhnceafaenchbefokkngcbnejached|ogogpebnagniggbnkbpjioobomdbmdcj|ldmnhdllijbchflpbmnlgndfnlgmkgif|lnajjhohknhgemncbaomjjjpmpdigedg|aecccajigpipkpioaidignbgbeekglkd|akebbllmckjphjiojeioooidhnddnplj|akifdnfipbeoonhoeabdicnlcdhghmpn|akkkopcadaalekbdgpdikhdablkgjagd|alkfljfjkpiccfgbeocbbjjladigcleg|alllblhkgghelnejlggmmgjbkdabidie|amkkjdjjgiiamenbopfpdmjcleecjjgg|amnaljnjmgajgajelnplfmidgjgbjfhe|bbjdlbemjklojnbifkgameepcafflmem|bdnanfggeppmkfhkgmpojkhanoplkacc|bgdkbjcdecedfoejdfgeafdodjgfohno|bnchgibgpgmlickioneccggfobljmhjc|bpljfbcejldmgeoodnogeefaihjdgbam|cbnekafldflkmngbgmbnfmchjaelnhem|cdpiopekjeonfjeocbfebemgocjciepp|cehdkmmfadpplgchnbjgdngdcjmhlfcc|cljengcehefhflhoahaambmkknjekjib|clpgopiimdjcilllcjncdkoeikkkcfbi|cmeoegkmpbpcoabhlklbamfeidebgmdf|cmlbghnlnbjkdgfjlegkbjmadpbmlgjb|cnibdhllkgidlgmaoanhkemjeklneolk|cpnfioldnmhaihohppoaebillnambcgn|dbohcpohlgnhgjmfkakoniiplglpfhcb|dcamdpfclondppklabgkfaofjccpioil|dljlpildgknddpnahppkihgodokfjbnd|dlpiookhionidajbiopmaajeckifeehn|dmaibhbbpmdihedidicfeigilkbobcog|dohenclhhdfljpjlnpjnephpccbdgmmb|dpdemambcedffmnkfmkephnhhnclmcio|ejlcbfmhjbkgohopdkijfgggbikgbacb|eljfpgehlncincemdmmnebmnlcmfamhm|enmmilgindjmffoljaojkcgloakmloen|eoklnfefipnjfeknpmigmogeeepddcch|fddajeklkkggbnppabbhkdmnkdjindlo|fibgndhgobbaaekmnneapojgkcehaeac|fjfhejmbhpabkacpoddjbcfandjoacmb|flkdjodmoefccepdihipjdlianmkmhgc|fmajpchoiahphjiligpmghnhmabolhoh|gaafhblhbnkekenogcjniofhbicchlke|gbaoddbbpompjhmilbgiaapkkakldlpc|gbhhgipmedccnankkjchgcidiigmioio|gfhcdakcnpahfdealajmhcapnhhablbp|gipmochingljoikdjakkdolfcbphmlom|glofhphmolanicdaddgkmhfmjidjkaem|haochenfmhglpholokliifmlpafilfdc|hbobdcfpgonejphpemijgjddanoipbkj|hdmppejcahhppjhkncagagopecddokpi|heljkmdknlfhiecpknceodpbokeipigo|hiofkndodabpioiheinoiojjobadpgmj|hkbihmjhjmehlocilifheeaeiljabenb|hlmdnedepbbihmbddepemmbkenbnoegd|hmlnefhgicedcmebmkjdcogieefbaagl|hnpbijogiiaegambgpaenjbcbgaeimlf|ibelidmkbnjmmpjgfibbdbkamgcbnjdm|ihbkmfoadnfjgkpdmgcboiehapkiflme|ijccacgjefefdpglhclnbpfjlcbagafm|ijfmkphjcogaealhjgijjfjlkpdhhojk|ijpgccpmogehkjhdmomckpkfcpbjlmnj|imjmnghlhiimodfkdkgnfplhlobehnpm|jddinhnhplibccfmniaakhffpjpnaglp|jmopjanoebpdbopigcbpjhiigmjolikk|jnmmbmkmbkcccpihjgnhjmhhkokfdnfe|jodocbbdcdclkhjkibnlfhbmllcpfkfo|kahcolfecjbejjjadhjafmihdnifonjf|kblomapfkjidbbbdllmofkcakcenkmec|kbmindomjiejdikjaagfdbdfpnlanobi|kbnkkecifeppobnemkielnpagifkobki|kjnakdbpijigdbfepipnbafnhbcfdkga|kknakidneabpfgepadgpkibalcnabnnh|klglejfbdeipgklgaepnodpjcnhaihkd|kmiidcaojgeepjlccoalkdimgpfnbagj|lcijkepobdokkgmefebkiejhealgblle|lefndgfmmbdklidbkeifpgclmpnhcilg|lfkknbmaifjomagejflmjklcmpadmmdg|ljbgkfbiifhpgpipepnfefijldolkhlm|lmcpbhamfpbonaenickjclacodolkbdl|lmgenhmehbcolpikplhkoelmagdhoojn|maeccdadgnadblfddcmanhpofobhgfme|medkneifmjcpgmmibfppjpfjbkgbgebl|mheomooihiffmcgldolenemmplpgoahn|mmbbjakjlpmndjlbhihlddgcdppblpka|mmbkmjmlnhocfcnjmbchmflamalekbnb|nbgligggjfgkpphhghhjdoiefbimgooc|ncpdkpcgmdhhnmcjgiiifdhefmekdcnf|ndajcmifndknmkckdcdefkpgcodciggk|nelbpdjegmhhgpfcjclhdmkcglimkjpp|nkacmelgoeejhjgmmgflbcdhonpaplcg|nmegibgeklckejdlfhoadhhbgcdjnojb|nodobilhjanebkafmpihkpoabiggnnfl|oanpifaoclmgmflmddlgkikfaggejobn|ocflhkadmmnlbieoiiekfcdcmjcfeahe|odeccdcabdffpebnfancpkepjeecempn|oejhnncfanbaogjlbknmlgjpleachclf|ogbaedmbbmmipljceodeimlckohbnfan|ojkbafekojdcedacileemekjdfdpkbkf|pdgaknahllnfldmclpcllpieafkaibmf|peflgkmfmoijonfgcjdlpnnfdegnlaji|phfkdailnomcbcknpdmokejhellbecjb|pkghgkfjhjghinikeanecbgjehojfhdg|pllkanemicadpcmkfodglahcocfdgkhj|fpeabamapgecnidibdmjoepaiehokgda|pcdgkgbadeggbnodegejccjffnoakcoh|jkphinfhmfkckkcnifhjiplhfoiefffl/i
```

> [!WARNING]  
> This search is very expensive.

---

## Query 1 — Block-list hit (folder created with bad extension ID)

Detects the directory creation that fires once per extension install. `FileName` is the 32-char extension ID directly — no regex extraction needed. Cleaner and lower-volume than chasing every `*FileWritten` under the extension folder.

```java
#event_simpleName=DirectoryCreate
| FilePath=/(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Chromium|Vivaldi|Opera\sSoftware|Yandex)\\/
| FilePath=/(?i)\\Extensions\\?$/i
| FileName=/^[a-p]{32}$/
| FileName=/^(obifanppcpchlehkjipahhphbcbjekfa|mdcfennpfgkngnibjbpnpaafcjnhcjno|mmecpiobcdbjkaijljohghhpfgngpjmk|bfoofgelpmalhcmedaaeogahlmbkopfd|cbfhnceafaenchbefokkngcbnejached|ogogpebnagniggbnkbpjioobomdbmdcj|ldmnhdllijbchflpbmnlgndfnlgmkgif|lnajjhohknhgemncbaomjjjpmpdigedg|aecccajigpipkpioaidignbgbeekglkd|akebbllmckjphjiojeioooidhnddnplj|akifdnfipbeoonhoeabdicnlcdhghmpn|akkkopcadaalekbdgpdikhdablkgjagd|alkfljfjkpiccfgbeocbbjjladigcleg|alllblhkgghelnejlggmmgjbkdabidie|amkkjdjjgiiamenbopfpdmjcleecjjgg|amnaljnjmgajgajelnplfmidgjgbjfhe|bbjdlbemjklojnbifkgameepcafflmem|bdnanfggeppmkfhkgmpojkhanoplkacc|bgdkbjcdecedfoejdfgeafdodjgfohno|bnchgibgpgmlickioneccggfobljmhjc|bpljfbcejldmgeoodnogeefaihjdgbam|cbnekafldflkmngbgmbnfmchjaelnhem|cdpiopekjeonfjeocbfebemgocjciepp|cehdkmmfadpplgchnbjgdngdcjmhlfcc|cljengcehefhflhoahaambmkknjekjib|clpgopiimdjcilllcjncdkoeikkkcfbi|cmeoegkmpbpcoabhlklbamfeidebgmdf|cmlbghnlnbjkdgfjlegkbjmadpbmlgjb|cnibdhllkgidlgmaoanhkemjeklneolk|cpnfioldnmhaihohppoaebillnambcgn|dbohcpohlgnhgjmfkakoniiplglpfhcb|dcamdpfclondppklabgkfaofjccpioil|dljlpildgknddpnahppkihgodokfjbnd|dlpiookhionidajbiopmaajeckifeehn|dmaibhbbpmdihedidicfeigilkbobcog|dohenclhhdfljpjlnpjnephpccbdgmmb|dpdemambcedffmnkfmkephnhhnclmcio|ejlcbfmhjbkgohopdkijfgggbikgbacb|eljfpgehlncincemdmmnebmnlcmfamhm|enmmilgindjmffoljaojkcgloakmloen|eoklnfefipnjfeknpmigmogeeepddcch|fddajeklkkggbnppabbhkdmnkdjindlo|fibgndhgobbaaekmnneapojgkcehaeac|fjfhejmbhpabkacpoddjbcfandjoacmb|flkdjodmoefccepdihipjdlianmkmhgc|fmajpchoiahphjiligpmghnhmabolhoh|gaafhblhbnkekenogcjniofhbicchlke|gbaoddbbpompjhmilbgiaapkkakldlpc|gbhhgipmedccnankkjchgcidiigmioio|gfhcdakcnpahfdealajmhcapnhhablbp|gipmochingljoikdjakkdolfcbphmlom|glofhphmolanicdaddgkmhfmjidjkaem|haochenfmhglpholokliifmlpafilfdc|hbobdcfpgonejphpemijgjddanoipbkj|hdmppejcahhppjhkncagagopecddokpi|heljkmdknlfhiecpknceodpbokeipigo|hiofkndodabpioiheinoiojjobadpgmj|hkbihmjhjmehlocilifheeaeiljabenb|hlmdnedepbbihmbddepemmbkenbnoegd|hmlnefhgicedcmebmkjdcogieefbaagl|hnpbijogiiaegambgpaenjbcbgaeimlf|ibelidmkbnjmmpjgfibbdbkamgcbnjdm|ihbkmfoadnfjgkpdmgcboiehapkiflme|ijccacgjefefdpglhclnbpfjlcbagafm|ijfmkphjcogaealhjgijjfjlkpdhhojk|ijpgccpmogehkjhdmomckpkfcpbjlmnj|imjmnghlhiimodfkdkgnfplhlobehnpm|jddinhnhplibccfmniaakhffpjpnaglp|jmopjanoebpdbopigcbpjhiigmjolikk|jnmmbmkmbkcccpihjgnhjmhhkokfdnfe|jodocbbdcdclkhjkibnlfhbmllcpfkfo|kahcolfecjbejjjadhjafmihdnifonjf|kblomapfkjidbbbdllmofkcakcenkmec|kbmindomjiejdikjaagfdbdfpnlanobi|kbnkkecifeppobnemkielnpagifkobki|kjnakdbpijigdbfepipnbafnhbcfdkga|kknakidneabpfgepadgpkibalcnabnnh|klglejfbdeipgklgaepnodpjcnhaihkd|kmiidcaojgeepjlccoalkdimgpfnbagj|lcijkepobdokkgmefebkiejhealgblle|lefndgfmmbdklidbkeifpgclmpnhcilg|lfkknbmaifjomagejflmjklcmpadmmdg|ljbgkfbiifhpgpipepnfefijldolkhlm|lmcpbhamfpbonaenickjclacodolkbdl|lmgenhmehbcolpikplhkoelmagdhoojn|maeccdadgnadblfddcmanhpofobhgfme|medkneifmjcpgmmibfppjpfjbkgbgebl|mheomooihiffmcgldolenemmplpgoahn|mmbbjakjlpmndjlbhihlddgcdppblpka|mmbkmjmlnhocfcnjmbchmflamalekbnb|nbgligggjfgkpphhghhjdoiefbimgooc|ncpdkpcgmdhhnmcjgiiifdhefmekdcnf|ndajcmifndknmkckdcdefkpgcodciggk|nelbpdjegmhhgpfcjclhdmkcglimkjpp|nkacmelgoeejhjgmmgflbcdhonpaplcg|nmegibgeklckejdlfhoadhhbgcdjnojb|nodobilhjanebkafmpihkpoabiggnnfl|oanpifaoclmgmflmddlgkikfaggejobn|ocflhkadmmnlbieoiiekfcdcmjcfeahe|odeccdcabdffpebnfancpkepjeecempn|oejhnncfanbaogjlbknmlgjpleachclf|ogbaedmbbmmipljceodeimlckohbnfan|ojkbafekojdcedacileemekjdfdpkbkf|pdgaknahllnfldmclpcllpieafkaibmf|peflgkmfmoijonfgcjdlpnnfdegnlaji|phfkdailnomcbcknpdmokejhellbecjb|pkghgkfjhjghinikeanecbgjehojfhdg|pllkanemicadpcmkfodglahcocfdgkhj|fpeabamapgecnidibdmjoepaiehokgda|pcdgkgbadeggbnodegejccjffnoakcoh|jkphinfhmfkckkcnifhjiplhfoiefffl)$/
| groupBy([FileName, ComputerName],
          function=[min(@timestamp, as=FirstSeen),
                    max(@timestamp, as=LastSeen),
                    collect([FilePath, UserName])])
| sort(FirstSeen, order=asc)
```

---

## Query 2 — Force-installed via Group Policy / MDM

Hits writes to the `ExtensionInstallForcelist` policy key — used by legitimate admin pushes **and** by malware persisting via policy. Combine with the bad-list to focus on the latter.

```java
#event_simpleName=/RegSystemConfigValueUpdate|RegGenericValueUpdate/i
| RegObjectName=/(?i)\\SOFTWARE\\Policies\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave)\\ExtensionInstallForcelist/
// RegStringValue typically: "<extid>;https://clients2.google.com/service/update2/crx"
| regex("(?<ExtensionId>[a-p]{32})", field=RegStringValue, strict=false)
| ExtensionId=/^(obifanppcpchlehkjipahhphbcbjekfa|mdcfennpfgkngnibjbpnpaafcjnhcjno|mmecpiobcdbjkaijljohghhpfgngpjmk|bfoofgelpmalhcmedaaeogahlmbkopfd|cbfhnceafaenchbefokkngcbnejached|ogogpebnagniggbnkbpjioobomdbmdcj|ldmnhdllijbchflpbmnlgndfnlgmkgif|lnajjhohknhgemncbaomjjjpmpdigedg|aecccajigpipkpioaidignbgbeekglkd|akebbllmckjphjiojeioooidhnddnplj|akifdnfipbeoonhoeabdicnlcdhghmpn|akkkopcadaalekbdgpdikhdablkgjagd|alkfljfjkpiccfgbeocbbjjladigcleg|alllblhkgghelnejlggmmgjbkdabidie|amkkjdjjgiiamenbopfpdmjcleecjjgg|amnaljnjmgajgajelnplfmidgjgbjfhe|bbjdlbemjklojnbifkgameepcafflmem|bdnanfggeppmkfhkgmpojkhanoplkacc|bgdkbjcdecedfoejdfgeafdodjgfohno|bnchgibgpgmlickioneccggfobljmhjc|bpljfbcejldmgeoodnogeefaihjdgbam|cbnekafldflkmngbgmbnfmchjaelnhem|cdpiopekjeonfjeocbfebemgocjciepp|cehdkmmfadpplgchnbjgdngdcjmhlfcc|cljengcehefhflhoahaambmkknjekjib|clpgopiimdjcilllcjncdkoeikkkcfbi|cmeoegkmpbpcoabhlklbamfeidebgmdf|cmlbghnlnbjkdgfjlegkbjmadpbmlgjb|cnibdhllkgidlgmaoanhkemjeklneolk|cpnfioldnmhaihohppoaebillnambcgn|dbohcpohlgnhgjmfkakoniiplglpfhcb|dcamdpfclondppklabgkfaofjccpioil|dljlpildgknddpnahppkihgodokfjbnd|dlpiookhionidajbiopmaajeckifeehn|dmaibhbbpmdihedidicfeigilkbobcog|dohenclhhdfljpjlnpjnephpccbdgmmb|dpdemambcedffmnkfmkephnhhnclmcio|ejlcbfmhjbkgohopdkijfgggbikgbacb|eljfpgehlncincemdmmnebmnlcmfamhm|enmmilgindjmffoljaojkcgloakmloen|eoklnfefipnjfeknpmigmogeeepddcch|fddajeklkkggbnppabbhkdmnkdjindlo|fibgndhgobbaaekmnneapojgkcehaeac|fjfhejmbhpabkacpoddjbcfandjoacmb|flkdjodmoefccepdihipjdlianmkmhgc|fmajpchoiahphjiligpmghnhmabolhoh|gaafhblhbnkekenogcjniofhbicchlke|gbaoddbbpompjhmilbgiaapkkakldlpc|gbhhgipmedccnankkjchgcidiigmioio|gfhcdakcnpahfdealajmhcapnhhablbp|gipmochingljoikdjakkdolfcbphmlom|glofhphmolanicdaddgkmhfmjidjkaem|haochenfmhglpholokliifmlpafilfdc|hbobdcfpgonejphpemijgjddanoipbkj|hdmppejcahhppjhkncagagopecddokpi|heljkmdknlfhiecpknceodpbokeipigo|hiofkndodabpioiheinoiojjobadpgmj|hkbihmjhjmehlocilifheeaeiljabenb|hlmdnedepbbihmbddepemmbkenbnoegd|hmlnefhgicedcmebmkjdcogieefbaagl|hnpbijogiiaegambgpaenjbcbgaeimlf|ibelidmkbnjmmpjgfibbdbkamgcbnjdm|ihbkmfoadnfjgkpdmgcboiehapkiflme|ijccacgjefefdpglhclnbpfjlcbagafm|ijfmkphjcogaealhjgijjfjlkpdhhojk|ijpgccpmogehkjhdmomckpkfcpbjlmnj|imjmnghlhiimodfkdkgnfplhlobehnpm|jddinhnhplibccfmniaakhffpjpnaglp|jmopjanoebpdbopigcbpjhiigmjolikk|jnmmbmkmbkcccpihjgnhjmhhkokfdnfe|jodocbbdcdclkhjkibnlfhbmllcpfkfo|kahcolfecjbejjjadhjafmihdnifonjf|kblomapfkjidbbbdllmofkcakcenkmec|kbmindomjiejdikjaagfdbdfpnlanobi|kbnkkecifeppobnemkielnpagifkobki|kjnakdbpijigdbfepipnbafnhbcfdkga|kknakidneabpfgepadgpkibalcnabnnh|klglejfbdeipgklgaepnodpjcnhaihkd|kmiidcaojgeepjlccoalkdimgpfnbagj|lcijkepobdokkgmefebkiejhealgblle|lefndgfmmbdklidbkeifpgclmpnhcilg|lfkknbmaifjomagejflmjklcmpadmmdg|ljbgkfbiifhpgpipepnfefijldolkhlm|lmcpbhamfpbonaenickjclacodolkbdl|lmgenhmehbcolpikplhkoelmagdhoojn|maeccdadgnadblfddcmanhpofobhgfme|medkneifmjcpgmmibfppjpfjbkgbgebl|mheomooihiffmcgldolenemmplpgoahn|mmbbjakjlpmndjlbhihlddgcdppblpka|mmbkmjmlnhocfcnjmbchmflamalekbnb|nbgligggjfgkpphhghhjdoiefbimgooc|ncpdkpcgmdhhnmcjgiiifdhefmekdcnf|ndajcmifndknmkckdcdefkpgcodciggk|nelbpdjegmhhgpfcjclhdmkcglimkjpp|nkacmelgoeejhjgmmgflbcdhonpaplcg|nmegibgeklckejdlfhoadhhbgcdjnojb|nodobilhjanebkafmpihkpoabiggnnfl|oanpifaoclmgmflmddlgkikfaggejobn|ocflhkadmmnlbieoiiekfcdcmjcfeahe|odeccdcabdffpebnfancpkepjeecempn|oejhnncfanbaogjlbknmlgjpleachclf|ogbaedmbbmmipljceodeimlckohbnfan|ojkbafekojdcedacileemekjdfdpkbkf|pdgaknahllnfldmclpcllpieafkaibmf|peflgkmfmoijonfgcjdlpnnfdegnlaji|phfkdailnomcbcknpdmokejhellbecjb|pkghgkfjhjghinikeanecbgjehojfhdg|pllkanemicadpcmkfodglahcocfdgkhj|fpeabamapgecnidibdmjoepaiehokgda|pcdgkgbadeggbnodegejccjffnoakcoh|jkphinfhmfkckkcnifhjiplhfoiefffl)$/
| table([@timestamp, ComputerName, UserName, ExtensionId, RegObjectName, RegStringValue])
| sort(@timestamp, order=desc)
```

---

## Query 3 — Tenant-wide extension inventory (no bad-list)

Surfaces every extension directory creation seen across the tenant, with first/last seen and host count. Use as a baseline or to triage incidents where the actor's ID isn't in any public bad-list yet.

```java
#event_simpleName=DirectoryCreate
| FilePath=/(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Chromium|Vivaldi|Opera Software|Yandex)\\/
| FilePath=/(?i)\\Extensions\\[a-p]{32}$/
| regex("(?<ExtensionId>[a-p]{32})$", field=FilePath, strict=true)
| groupBy([ExtensionId],
          function=[
            count(as=InstallCount),
            count(field=aid, distinct=true, as=HostCount),
            min(@timestamp, as=FirstSeen),
            max(@timestamp, as=LastSeen),
            collect(fields=[ComputerName], limit=20, separator=", ")
          ])
| Hosts := ComputerName
// Tune for novelty — extensions seen on very few hosts are higher-signal
| HostCount < 5
| sort(LastSeen, order=desc)
```

---

## Notes

- Extension IDs are **deterministic** — derived from the SHA-256 of the public key in the CRX. They cannot be rotated without breaking the extension's update channel. This is the durable invariant.
- Sideloaded / unpacked extensions get a random ID and won't match a static bad-list. **Query 3** (inventory mode) is the answer for those — anomalous IDs on a tiny number of hosts.
- Chrome / Edge / Brave / Vivaldi / Opera / Yandex / Chromium all share the same `User Data\…\Extensions\<id>` layout — the regex covers all of them.
- For users running a **non-default Chrome profile** (`Profile 1`, `Profile 2`, …), the regex `[^\\]+` in the `User Data` segment handles every profile name.

## Coverage map

| Campaign | IDs | Source |
|---|---|---|
| Socket — cloudapi.stream MaaS | 108 | https://socket.dev/blog/108-chrome-ext-linked-to-data-exfil-session-theft-shared-c2 |
| Unit 42 — Chrome MCP Server RAT | 1 | https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-02-11-IOCs-for-RAT-disguinsed-as-AI-based-browser-extension.txt |
| Socket — VKfeed | 1 | https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html |
| Socket — CL Suite by @CLMasters | 1 | https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html |
| **Total** | **111** | |
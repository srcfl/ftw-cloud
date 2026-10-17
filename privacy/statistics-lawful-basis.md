# Rättslig grund och mottagare – beslutsunderlag

17 oktober 2026. Utkast, inte juridiskt godkänt. Avser 48-timmarspolicyn
`ftw-project-stats-2026-10-v3`. [DPIA](project-statistics-dpia.md) innehåller
aktiveringsspärren. Ansvarig behöver avgöra punkterna nedan; en UI-granskning
eller ett allmänt önskemål om statistik ersätter inte det beslutet.

## Cloud: pröva artikel 6.1 f före start

Det konkreta intresset är att mäta rapporterande installationer, registrerad
energi och inställd kapacitet, följa FTW:s användning och förbättra planering.
Ingen reklam, handel med hushållsdata, individuell profilering eller beslut
om en boende ingår. Affärsintresse kan vara berättigat men räcker inte ensamt.

Avtal, artikel 6.1 b, föreslås inte som grund för projektstatistik: appens
fjärråtkomst behöver inte i sig ett register med hushållens timenergi. Att
lägga in ett krav i Cloud-villkoren skapar inte den nödvändigheten.
Samtycke föreslås inte som grund för obligatorisk Cloud-statistik, eftersom
personen inte kan säga nej och behålla Cloud. En ny bedömning före denna nya
behandling är inte ett byte av grund för redan insamlade timrader.

| Prövning | Bedömning och kvarstående beslut |
|---|---|
| Kan fälten nå syftet? | Ja för registrerad energi och inställd kapacitet. De bevisar inte faktisk styrförmåga, besparing eller antal personer. |
| Behövs hushålls-id? | Ett slump-id och koppling till hemmet ger dubblettskydd, gruppregler och radering. Namn, adress och enhets-id behövs inte. |
| Behövs timrader? | De möjliggör ett löpande dygn och kontroll per bidragande hem. Ett enda fast dagsvärde per hem vore mindre detaljerat och måste vägas mot behovet av ett löpande dygn. |
| Behövs 13 månader? | Nej för den aktuella funktionen. Fredrik valde 48 timmar den 17 oktober; årsanalys av hushållsrader ingår inte. Publicerade gruppvärden sparas i 90 dagar. |
| Måste alla Cloud-hem bidra? | Ägaren vill ha täckning för hela Cloud. Frivilliga bidrag ger urvalsfel men når ändå delar av syftet. Det återstår att visa varför detta väger tyngre än ett mindre ingripande, frivilligt urval eller grövre dagsdata. Kravet är inte bevisat nödvändigt av kod eller villkor. |
| Vad väntar sig boende? | Energiappen gör energiuppgifter väntade, men inte automatiskt deras vidare användning i projektstatistik. Tydlig ny information krävs. Andra boende har inte nödvändigtvis sett appen. |
| Vad kan skada? | Timdata kan visa vanor, laddning och närvaro. Barn kan ingå i hemmet. Inga personprofiler görs men slutsatser kan ändå dras vid intrång eller differensanalys. |
| Vilka skydd finns? | 48 timmar, få fält, avslutade timmar, avrundning, inga platser, minst 20 hem, högst 30 procent dominans, avstängd startflagga, versionskrav, rättighetsrutin och spärr mot återuppladdning. |
| Kan personen invända? | Ja, begäran ska bedömas individuellt enligt artikel 21. Ett standardsvar att ”Cloud kräver statistik” är ingen sådan bedömning. Rättighetsrutinen kan begränsa insamling och Cloud under prövningen. Ansvarig ska avgöra skälen och följden för fortsatt tjänst. |

**Slutsats i utkastet:** artikel 6.1 f är en grund att pröva, inte en grund
som detta dokument kan bekräfta. Den obligatoriska omfattningens nödvändighet,
avvägningen för andra boende och följden av en invändning återstår för
ansvarig/juridisk granskare. Om prövningen inte håller: ändra omfattningen,
exempelvis till frivilliga bidrag eller grövre dagsdata, före start. Behåll
aktiveringsflaggan tom tills beslutet är dokumenterat.

## Lokal drift: föreslaget särskilt samtycke

Ja är huvudvalet, Nej finns bredvid. Ingen rapport går före ett aktivt svar.
Nej och återkallelse lämnar lokal styrning kvar. Det talar för frivillighet
men är inget färdigt rättsligt godkännande. Informationen anger fält, syfte,
åtkomst, 48 timmar och gruppvärdenas kvarvaro. Boxen sparar version och tid;
ny version behöver nytt svar och rapporterar inga tidigare timmar.

Pröva vem som får svara för hushållets uppgifter, hur andra boende informeras
och om [9 kap. 28 § LEK](https://www.riksdagen.se/sv/dokument-och-lagar/dokument/svensk-forfattningssamling/lag-2022482-om-elektronisk-kommunikation_sfs-2022-482/) ställer egna krav för läsning
eller lagring i terminalutrustning. Ett godkännande av villkor ersätter inte
en sådan prövning. Informera andra boende före delning; möjliggör deras
rättighetsbegäran utan att kräva att de själva äger boxnyckeln.

## Mottagare och överföringar

| Mottagare | Faktisk väg och avtalsunderlag |
|---|---|
| AWS | EC2/EBS i Stockholm lagrar rader. KMS, SSM och Secrets Manager stödjer drift och nycklar. AWS anger att dess DPA ingår i Service Terms och gäller automatiskt för kunder som behandlar personuppgifter. Spara avtalets gällande version och bekräfta att rätt Sourceful-bolag är kund. Detta är inte ett bevis på företagets faktiska avtalsidentitet. |
| AWS infrastruktur | AWS listar Amazon Data Services Sweden AB för Stockholm. Läs hela aktuella underbiträdeslistan för de använda tjänsterna. Globala supportenheter kan beröras om Sourceful delar kunddata i ett supportärende. |
| Cloudflare | Stats-Worker tar bara det publika grupp-API:ets svar. Ingen hushållsrad eller hemnyckel ska skickas dit. Besökarnas webbtrafik är en separat behandling. Gruppreglerna bevisar inte anonymitet mot all hjälpinformation. |
| Apple | App Privacy ska omfatta Cloud, identifierare och ny statistik. Appen innehåller ingen annonsanalys. Hemmens timrader skickas inte som APNs-innehåll av denna statistikväg. Apples egna TestFlight-/App Store-data ingår inte i installationstalet på stats-sidan. |
| Sourcefuls operatörer | Administratörer kan läsa data på värden. Ett verifierat rättighetsärende kan ge ett avgränsat offlineutdrag; ingen allmän personalroute finns. Tillträdeslista ska godtas av ansvarig. |

Stockholm som lagringsregion bevisar inte att all möjlig åtkomst stannar i
EES. AWS beskriver SCC och kompletterande skydd i sin DPA. Innan start ska
ansvarig godta överföringsbedömningen för den faktiska avtalskedjan. Ge inte
AWS-support databasdump, persondata eller nycklar som rutin; pröva varje sådant
utlämnande först. Ingen AI-tjänst får hushållens statistik i denna väg.

## Förteckning över behandlingen, artikel 30

- Ansvarig: Sourceful Labs AB, 559382-0458, Kalmar; support@sourceful.energy.
- Ändamål: FTW-projektets energi-, kapacitets- och användningsstatistik.
- Berörda: boende i rapporterande hem; inte bara den som äger boxen.
- Uppgifter: slump-id, hemkoppling, policy/tid, avrundade avslutade timmar och
  inställd kapacitet; inga namn eller platsfält i statistikrapporten.
- Grund: föreslaget lokalt samtycke; Cloud väntar på prövningen ovan.
- Mottagare, överföringar: tabellen ovan. Ingen uthyrning av data.
- Gallring: hushållstimmar 48 timmar; publicerade gruppögonblick 90 dagar;
  rättighetsärendets bevis följer företagets separat beslutade ärenderegler.
- Skydd och rättigheter: [driftrutinen](statistics-operations.md) och DPIA.
- Omfattning: inga timrader samlas innan besluten och aktiveringen är klara.

Källor kontrollerade 17 oktober 2026:
[IMY om rättslig grund](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/rattslig-grund/),
[intresseavvägning](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/rattslig-grund/intresseavvagning/),
[onlinetjänster och avtal](https://www.imy.se/verksamhet/dataskydd/dataskydd-pa-olika-omraden/foretag/behandling-av-personuppgifter-vid-tillhandahallande-av-onlinetjanster/),
[AWS DPA](https://docs.aws.amazon.com/whitepapers/latest/navigating-gdpr-compliance/in-detail.html),
[AWS underbiträden](https://aws.amazon.com/compliance/sub-processors/).

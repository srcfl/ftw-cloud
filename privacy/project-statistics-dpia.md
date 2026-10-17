# FTW projektstatistik – underlag för konsekvensbedömning

Datum: 17 oktober 2026. Status: utkast för granskning. Inte signerat.

Detta underlag beskriver den avgränsade behandlingen under policyn
`ftw-project-stats-2026-10-v3`. Det ger inget tillstånd att starta insamlingen.
ADR 0008, C8, kräver signerad konsekvensbedömning. Ansvarig företrädare för
Sourceful Labs AB ska ta ställning till underlaget, öppna frågor och kvarvarande
risker före aktivering. Juridisk granskning och dataskyddsombudets råd, om ett
ombud finns, ska dokumenteras. Utkastet avgör inte om artikel 35 i sig kräver
en bedömning i just detta fall; projektets eget krav gäller tills vidare.

## Ändamål och omfattning

Sourceful vill förstå hur rapporterande hem använder och flyttar
energi, förbättra FTW:s planering och publicera gruppsummor på stats.ftw.energy.
Ingen reklam, spårning mellan tjänster, individuell profilering, beslut om ett
hushåll eller styrning av utrustning ingår i denna behandling. En assistents
åtkomst är en annan behandling med ett annat tillstånd.

Personuppgiftsansvarig: Sourceful Labs AB, org.nr 559382-0458, Kalmar.
Kontakt i den befintliga integritetstexten: support@sourceful.energy.
Berörda: de hushåll där en behörig ägare väljer att bidra. Andra boende kan
beröras av vad energimönstren avslöjar. Partnerstyrda installationer, inklusive
aktiverad Nova, bidrar inte genom denna kodväg. Lokal boxdrift fungerar utan statistik; den nya Cloud-modellen kräver bidrag.

## Produktbeslut den 17 oktober 2026

Fredrik har valt två flöden. Statistik ingår för alla som använder FTW Cloud,
inklusive app- och assistentåtkomst. Den har inget eget av-val inom Cloud.
Ägaren behöver läsa och godta nya, tydliga Cloud-villkor; ett tidigare
Cloud-val eller statistikkryss godtar inte den nya omfattningen. Den som inte
vill bidra ska kunna använda boxen lokalt utan Cloud.

Den som använder FTW lokalt får i stället frågan om att bidra till samma
projektstatistik. Ja är det föreslagna valet, men ingen ny insamling startar
innan ett aktivt svar. Det är inte en förkryssad ruta eller ett samtycke genom
passivitet. Ett nej stänger av bidraget utan att ändra lokal drift.
Statistikläget publicerar inga telefonnycklar, parkopplingskoder, Noise-nycklar,
läsrättigheter eller livevärden och ger ingen fjärråtkomst.

Detta ersätter det tidigare förslaget om en separat statistikknapp för
Cloud-användare. Kodgrunden med avstängd insamling och publika dagsrapporter
har rullats ut. Version 2 av villkor och lokalfråga fick UI-granskning och släpptes i Core
och iOS. Fredrik valde därefter 48 timmars lagring i stället för 13 månader.
Version 3 kräver därför ett nytt svar; ändringen utvidgar inte insamlingen.
En ny kodrelease startar inte insamlingen.

## Uppgifter och flöde

| Steg | Uppgifter och hantering |
|---|---|
| Lokal box | Läser senaste avslutade UTC-timmen ur energiboken och konfigurationen. Inget före de nya Cloud-villkoren eller det lokala svaret laddas upp. Saknade värden utelämnas. |
| Rapport | Slumpmässigt 128-bitars statistik-id, policyversion, timstart, registrerad nätimport/export, solproduktion, batteriladdning/urladdning, billaddning/urladdning, inställd batterikapacitet, batteri-/laddareffekt och solkapacitet. Avrundning till 10 Wh eller W. Inga namn, adresser, koordinater, enhets-id:n, fordons-id:n, priser, friare text eller loggar. |
| FTW Cloud | Verifierar boxens signatur och aktuell policy och ägarens svar. Kopplar raden till hemmets Cloud-id för radering. En rad per hem och timme; omsändning ersätter raden. Stockholm, AWS eu-north-1 enligt driftsbeskrivningen. |
| Lagring | SQLite på Cloud-värdens beständiga disk. Timrader gallras efter 48 timmar. Avslutat Cloud, stoppad lokal delning och hemradering tar bort opublicerade rader när Cloud tar emot begäran. Offline återkallelse når Cloud vid nästa anslutning. |
| Publicering | Senaste 24 avslutade timmarna. Kapacitet från respektive hems senaste rapport; energi från dess registrerade timmar. Minst 20 bidragande hem per värde, inget hem över 30 procent av summan. Worker i Cloudflare får bara redan publika gruppvärden och sparar publicerade ögonblicksbilder i 90 dagar. |

Raderna i Cloud är personuppgifter, inte anonym data: tjänsten kan knyta dem
till ett hem. TLS skyddar transporten men Sourceful kan läsa rapporten.
Den som har full kontroll över värden kan läsa databas och minne. Det finns
ingen webbroute där personal kan läsa ett enskilt hems timrader. Ett avgränsat
offlineverktyg kan ge registerutdrag eller radera statistik för ett verifierat
rättighetsärende. Cloud måste vara stoppat; ingen ny personalbehörighet delas
ut av verktyget. Full värdåtkomst medger redan teknisk åtkomst till databasen.

IP-adresser och anslutningstider kan synas vid transporten. Appkoden avser inte
att logga adresser. Kontrollen nedan beskriver faktiska driftinställningar. Den bevisar inte att
varje tänkbar logg är fri från uppgifter eller att ingen annan kopia har gjorts.

## Avgränsad driftkontroll den 17 oktober 2026

Kontrollen läste metadata för den befintliga FTW-värden och dess relevanta
behörigheter. Den läste inga hushållsrader och ändrade ingen AWS-resurs.

| Kontroll | Faktiskt resultat |
|---|---|
| Värd och nät | EC2 t4g.small, Amazon Linux 2023, Stockholm. IMDSv2 krävs, hop limit 1, ingen SSH-nyckel. Säkerhetsgruppen tillåter TCP/UDP 443 från IPv4-internet, ingen SSH; utgående trafik är öppen. |
| Disk och KMS | 20 GiB gp3, krypterad, raderas med instansen. AWS-hanterad `aws/ebs`-nyckel, aktiverad. Nyckelpolicyn tillåter EBS-användning för behöriga principer i kontot via EC2 i Stockholm. Den isolerar inte FTW från kontots administratörer eller bred EC2-behörighet. |
| Operatörer | Fem IAM-användare i administratörsgruppen har `AdministratorAccess`. Därutöver finns en IP-villkorad bred användarpolicy och automation med bred EC2-behörighet. Privata person- och behörighetsdetaljer ska hållas i företagets åtkomstregister, inte i detta publika repo. Full effektiv åtkomst och återkommande granskning behöver ansvarigs beslut. |
| Tjänstnycklar | Cloud-värdens roll får anta FTW:s nyckelroll. Den rollens KMS-rättigheter gäller separata agent- och signeringsnycklar. Detta skyddar agentnycklarnas väg; det gör inte hushållsrader oläsbara för en värdadministratör. |
| Konto | Delat Sourceful-konto, även organisationens managementkonto. Driftdokumentet anger eget FTW-konto vid riktiga användare. Det kravet är inte uppfyllt av denna kontroll och har inte strukits. Ingen ändring av andra projekts IAM har gjorts. |
| Container | Skrivskyddat rotfilsystem, alla capabilities borttagna, `no-new-privileges`; nycklar från skrivskyddade tmpfs-mounts och skilda användare/volymer för nyckeltjänsten. Swap saknas; core dumps går till `/bin/false`. |
| Loggar | Docker `json-file`, tre filer om 10 MiB per container; ingen åldersgräns. CloudTrail Event History visar faktiska SSM-anrop, inklusive driftkontroll och deploy. Ingen trail, Event Data Store eller egen Session Manager-logginställning hittades i regionen. API-historik är inte en full kommandoinspelning. |
| Backup | Inga EC2-snapshots för FTW-volymen, inga skyddade AWS Backup-resurser i regionen, ingen upptäckt schemalagd backupväg på värden. Andra regioner och alla tänkbara manuella kopior ingår inte i detta bevis. Ingen statistikbackup ska införas utan ny gallrings- och återställningsbedömning. |
| Patchning | Värdens fråga om tillgängliga säkerhetsuppdateringar gav inga rader och exit 0. Det bevisar inte en fortlöpande patchrutin. |
| Insamling | `FTW_CLOUD_STATISTICS_POLICY` är tom i produktion. `/v1/stats` svarar 503 med `Ftw-Statistics-State: disabled`. |

Lagringen minskar från 13 månader till 48 timmar. Underhåll går varje minut,
även när insamlingen är avstängd. Rader över gränsen gallras vid nästa körning;
vid driftstopp sker fysisk gallring när processen åter är igång. SQLite använder
`secure_delete`; offline-raderingsverktyget tömmer även WAL. Ingen backup ingår.
Tillfälliga rättighetsutdrag ska få separat, kort livstid enligt
[operatörsrutinen](statistics-operations.md).

## Nödvändighet, proportionalitet och samtycke

Rättslig grund för den obligatoriska Cloud-modellen är ännu inte fastställd.
Att skriva statistik i avtalsvillkoren gör den inte i sig nödvändig för att
fullgöra avtalet. IMY skiljer mellan att godta villkor och att lämna samtycke;
samtycke till ett ändamål som inte behövs för tjänsten kan inte utan
vidare göras till ett krav för tjänsten. Tydlig information löser inte den
frågan. Juridisk granskare och ansvarig ska avgöra om modellen har en giltig
grund, pröva nödvändighet och alternativ samt dokumentera beslutet. Om ingen
grund håller måste Cloud-modellen ändras före start.

För lokala bidrag är informerat, särskilt och frivilligt samtycke den
föreslagna grunden. Boxen frågar först, med Ja som huvudknapp; den skickar
inte före svaret. Nej och senare avstängning påverkar inte lokal styrning.
Även här ska granskningen pröva andra boendes ställning och eventuella
regler om åtkomst till terminalutrustning.

Informationen ska finnas på svenska och engelska: fält, ändamål, Sourcefuls
åtkomst, lagring, gruppregler och radering. Boxen sparar version, vem som
svarade och tid. Äldre val godtar inte den nya omfattningen. En ny policy ger
nytt statistik-id och nytt startdatum. Timmar före det bidrar inte. Att stänga
av Cloud stoppar fjärråtkomst och begär radering; lokala användare kan
stänga av bara statistiken. Redan publicerade gruppsummor finns kvar.

Alternativ som prövats: GitHub-nedladdningar säger inte om något installerats;
anonyma dagsrapporter kan uppskatta rapporterande aktiva installationer men
kan inte summera timenergi eller deduplicera hem. Endast publika gruppvärden
på boxen fungerar inte utan en gemensam sammanställning. Högre upplösning,
liveeffekt, adress, plats och hårdvaruid behövs inte och skickas inte.

48 timmar täcker den publika 24-timmarsvyn och en kort marginal för drift och
rättelse. Årsanalys med hushållsrader ingår inte. Publicerade gruppvärden får
finnas i 90 dagar. Längre lagring kräver nytt behov, ny bedömning och ny policy.

[Prövningen av rättslig grund](statistics-lawful-basis.md) beskriver möjliga
grunder, mindre ingripande alternativ, andra boende, terminalregler, mottagare,
AWS DPA och överföringar. Den är ett beslutsunderlag, inte ett fastställt
positivt rättsligt besked. Den innehåller även förteckningen enligt artikel 30.

## Risker och skydd

| Risk för de boende | Skydd som koden ger | Kvarvarande fråga |
|---|---|---|
| Ogiltig grund om Cloud villkoras med statistik | Versionerade, synliga villkor och teknisk aktiveringsspärr | Kritisk öppen fråga: villkor är inte i sig samtycke eller bevis på nödvändighet. Ingen aktivering före dokumenterat beslut. |
| Närvaro och vanor framgår av timenergi | Aktivt val av Cloud-villkor eller frivilligt lokalt bidrag, avslutade timmar, få fält, avrundning, inga platsfält | Timenergi kan ändå avslöja vanor. Ansvarig ska bedöma om risken är rimlig och hur andra boende informeras. |
| En ny policy följer med ett äldre val | Nytt policy-id, ingen automatisk återanvändning, box och Cloud kontrollerar policyn | Granska de renderade svenska och engelska skärmarna samt versionsflödet. |
| Återidentifiering ur små eller dominerade grupper | Minst 20 hem, högst 30 procent per hem, inga hushållsrader till Worker | Upprepade offentliga summor kan möjliggöra differensanalys. Trösklarna är inte ett bevis på anonymitet. Bedöm större eller fastare grupper före start om risken kvarstår. |
| Intrång eller missbruk av värdåtkomst | Signerade rapporter, snäva fält, ingen personalroute, SSH-fri SSM-drift, separata behörigheter för agentnycklar | Full administratör kan läsa data. EBS-kryptering har verifierats. Verifiera åtkomstlista, loggning, patchning och incidentväg. |
| Felaktiga slutsatser eller dubbla rapporter | Upsert per hem/timme, partnerfilter, okända värden utelämnas, konfigurering märks som sådan | Delvisa timmar och självrapporterad konfiguration bevisar inte fysisk styrning eller full dygnsproduktion. |
| Uppgifter lever kvar efter avstängning | Radering vid mottaget signerat återkallande, även när insamlingen är pausad; gallring efter 48 timmar | Ingen backup ingår. Offline-radering med varaktig spärr och återställd nyckel provas separat; en identitetskontroll behöver fortfarande utföras i det verkliga ärendet. |

Föreslagen riskbedömning: felaktig rättslig grund har hög kvarstående risk
och blockerar start. Värdåtkomst i delat konto och differensanalys av publika
summor har medelhög till hög kvarstående risk tills ansvarig prövat skydd och
alternativ. Kortare lagring och provad radering minskar följden av en läcka
men undanröjer inte den. Dessa nivåer är utkastets bedömning, inte ansvarigs
acceptans. Höga kvarvarande
risker får inte döljas med en sammanlagd poäng. Bedöm behovet av ytterligare
åtgärder och eventuellt förhandssamråd innan start.

## Bevis och återstående beslut

Kodgrund: srcfl/ftw#1693 och srcfl/ftw-cloud#31.
Den nya modellen: [Core #1700](https://github.com/srcfl/ftw/pull/1700),
[Cloud #32](https://github.com/srcfl/ftw-cloud/pull/32),
[iOS #87](https://github.com/srcfl/ftw-app/pull/87) och
[integritetstext #23](https://github.com/srcfl/ftw-web/pull/23).
Ägaren granskade de renderade Core-vyerna den 17 oktober. Det godkänner inte
att timinsamlingen startar. Relevanta tester täcker fält och
signering, äldre samtycke, serverns avstängda läge, gruppstorlek, dominans,
dubbletter, okända värden, återkallande, radering och gallring. En lokal testsvit
bevisar inte alla produktionskontroller eller ett giltigt rättsligt samtycke.

| Ursprunglig öppen punkt | Nuvarande bevis och det som återstår |
|---|---|
| 1. Information och val | Svenska/engelska app- och webbtexter samt Core-vyer finns. V2 fick ägarens UI-granskning. Fredrik granskade och godkände även de renderade Core-vyerna för V3 med 48 timmar den 17 oktober. Ingen faktisk hushållsaccept har lämnats av agenten. |
| 2. Rättslig grund | [Separat prövning](statistics-lawful-basis.md) finns. Obligatorisk Cloud-statistiks nödvändighet, andra boende, artikel 21 och terminalregler återstår för ansvarig/juridisk granskare. Villkor räcker inte ensamma. |
| 3. Biträden och överföringar | AWS:s DPA-väg och Stockholm-enhet är källbelagda. Faktisk avtalsidentitet, gällande avtalsversion och ansvarigs överföringsbedömning återstår. Cloudflare får bara publika celler. |
| 4. Drift | Faktiska inställningar står ovan. Ansvarig ska fastställa tillträdeslistan, kontoåtskillnaden enligt ADR, patch- och incidentansvar samt om loggskyddet räcker. Teknisk kryptering är verifierad; full isolering är det inte. |
| 5. Rättigheter | [Operatörsrutin](statistics-operations.md), privat offlineutdrag, radering/begränsning utan box och återställning med ursprunglig nyckel finns med prov på testdata. Radering stoppar återuppladdning efter omstart och lämnar ett annat hem orört. Utse operatör och privat ärende-/leveranskanal före start. |
| 6. Apple | App Privacy publicerades i Sourcefuls App Store Connect den 17 oktober 2026 efter Fredriks uttryckliga godkännande av slutintyget. UI visade ”Published a few seconds ago by Fredrik Ahlgren”. User ID och Other Data: funktion och analys; Device ID: funktion; alla kopplade, ingen reklamspårning. Integritetslänkar är sparade. Appmanifest och butikstext följer i den parade app-PR:en. Detta signerar inte DPIA eller startar timinsamlingen. |
| 7. Risk och beslut | Lagringsbeslutet är 48 timmar. Ansvarig ska besluta om kvarstående risker, eventuella villkor, juridiska slutsatser och om ytterligare samråd behövs. Underskrift saknas. |

Tekniska prov ersätter inte en verklig persons identitetskontroll, ett
biträdesavtal eller ansvarigs riskbeslut. Exakta kod- och testversioner ska
anges i det slutliga beslutet. Det får inte bara hänvisa till ”senaste version”.

Aktivering görs först efter beslut genom den exakta policyn i
`FTW_CLOUD_STATISTICS_POLICY`. Tomt värde är standard. Cloud annonserar då
ingen godkänd statistikpolicy och boxen skickar inga timrapporter. Rollback av
aktiveringen stoppar nya rapporter; radering och gallring fortsätter.

Beslut: väntar. Beslutsfattare: ej angiven. Datum och underskrift: saknas.
Ansvarig driftoperatör och incidentansvarig: ej utsedda i detta underlag.
Rådgivare/dataskyddsombud och råd: ej angivna.

Nästa översyn: före start, vid ändrat ändamål/fält, fler delade mottagare eller
shards, incident eller ny risk; därefter minst årligen.

## Vägledning som underlaget följer

- [IMY: hur en konsekvensbedömning ska genomföras](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/konsekvensbedomning/hur-ska-en-konsekvensbedomning-genomforas/).
- [IMY: när en konsekvensbedömning behövs](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/konsekvensbedomning/nar-ska-en-konsekvensbedomning-genomforas/).
- [IMY: samtycke och separata ändamål](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/rattslig-grund/samtycke/).
- [IMY: avtal och onlinetjänster](https://www.imy.se/verksamhet/dataskydd/dataskydd-pa-olika-omraden/foretag/behandling-av-personuppgifter-vid-tillhandahallande-av-onlinetjanster/).
- [EDPB: riktlinjer 05/2020 om samtycke](https://www.edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_202005_consent_en.pdf).

Underlaget skiljer tekniskt verifierade egenskaper från beslut som ansvarig
behöver fatta. Källorna ersätter inte granskning av just denna behandling.

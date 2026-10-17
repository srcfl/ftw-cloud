# FTW projektstatistik – underlag för konsekvensbedömning

Datum: 17 oktober 2026. Status: utkast för granskning. Inte signerat.

Detta underlag beskriver den avgränsade behandlingen under policyn
`ftw-project-stats-2026-10-v2`. Det ger inget tillstånd att starta insamlingen.
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
har rullats ut. Version 2 av villkor och lokalfråga behöver fortfarande
färdig kontroll, UI-granskning och beslut innan den aktiveras.

## Uppgifter och flöde

| Steg | Uppgifter och hantering |
|---|---|
| Lokal box | Läser senaste avslutade UTC-timmen ur energiboken och konfigurationen. Inget före de nya Cloud-villkoren eller det lokala svaret laddas upp. Saknade värden utelämnas. |
| Rapport | Slumpmässigt 128-bitars statistik-id, policyversion, timstart, registrerad nätimport/export, solproduktion, batteriladdning/urladdning, billaddning/urladdning, inställd batterikapacitet, batteri-/laddareffekt och solkapacitet. Avrundning till 10 Wh eller W. Inga namn, adresser, koordinater, enhets-id:n, fordons-id:n, priser, friare text eller loggar. |
| FTW Cloud | Verifierar boxens signatur och aktuell policy och ägarens svar. Kopplar raden till hemmets Cloud-id för radering. En rad per hem och timme; omsändning ersätter raden. Stockholm, AWS eu-north-1 enligt driftsbeskrivningen. |
| Lagring | SQLite på Cloud-värdens beständiga disk. Timrader gallras efter 13 månader. Avslutat Cloud, stoppad lokal delning och hemradering tar bort opublicerade rader när Cloud tar emot begäran. Offline återkallelse når Cloud vid nästa anslutning. |
| Publicering | Senaste 24 avslutade timmarna. Kapacitet från respektive hems senaste rapport; energi från dess registrerade timmar. Minst 20 bidragande hem per värde, inget hem över 30 procent av summan. Worker i Cloudflare får bara redan publika gruppvärden och sparar publicerade ögonblicksbilder i 90 dagar. |

Raderna i Cloud är personuppgifter, inte anonym data: tjänsten kan knyta dem
till ett hem. TLS skyddar transporten men Sourceful kan läsa rapporten.
Den som har full kontroll över värden kan läsa databas och minne. Det finns
ingen route där personal kan läsa ett enskilt hems timrader. Detta hindrar inte
teknisk åtkomst för en administratör med fulla värdrättigheter.

IP-adresser och anslutningstider kan synas vid transporten. Appkoden avser inte
att logga adresser. Infrastrukturens loggar, säkerhetskopior, underbiträden och
överföringar utanför EES behöver verifieras före beslut. Slutlig gallring i
säkerhetskopior kan inte påstås vara verifierad av databasens radtest.

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

13 månader är den föreslagna perioden för årsvariation. Ansvarig ska bekräfta
att årsanalysen faktiskt behövs; den publika 24-timmarsvyn behöver i sig inte
13 månaders hushållsrader. Om nyttan inte visas ska perioden kortas före start.

## Risker och skydd

| Risk för de boende | Skydd som koden ger | Kvarvarande fråga |
|---|---|---|
| Ogiltig grund om Cloud villkoras med statistik | Versionerade, synliga villkor och teknisk aktiveringsspärr | Kritisk öppen fråga: villkor är inte i sig samtycke eller bevis på nödvändighet. Ingen aktivering före dokumenterat beslut. |
| Närvaro och vanor framgår av timenergi | Aktivt val av Cloud-villkor eller frivilligt lokalt bidrag, avslutade timmar, få fält, avrundning, inga platsfält | Timenergi kan ändå avslöja vanor. Ansvarig ska bedöma om risken är rimlig och hur andra boende informeras. |
| En ny policy följer med ett äldre val | Nytt policy-id, ingen automatisk återanvändning, box och Cloud kontrollerar policyn | Granska de renderade svenska och engelska skärmarna samt versionsflödet. |
| Återidentifiering ur små eller dominerade grupper | Minst 20 hem, högst 30 procent per hem, inga hushållsrader till Worker | Upprepade offentliga summor kan möjliggöra differensanalys. Trösklarna är inte ett bevis på anonymitet. Bedöm större eller fastare grupper före start om risken kvarstår. |
| Intrång eller missbruk av värdåtkomst | Signerade rapporter, snäva fält, ingen personalroute, SSH-fri SSM-drift, separata behörigheter för agentnycklar | Full administratör kan läsa data. Verifiera åtkomstlista, loggning, diskkryptering, patchning och incidentväg. |
| Felaktiga slutsatser eller dubbla rapporter | Upsert per hem/timme, partnerfilter, okända värden utelämnas, konfigurering märks som sådan | Delvisa timmar och självrapporterad konfiguration bevisar inte fysisk styrning eller full dygnsproduktion. |
| Uppgifter lever kvar efter avstängning | Radering vid mottaget signerat återkallande, även när insamlingen är pausad; gallring efter 13 månader | Säkerhetskopiors livstid och radering efter förlorad box ska dokumenteras och provas. |

Risknivåer och acceptans är ännu inte fastställda av ansvarig. Höga kvarvarande
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

Före aktivering ska ansvarig fylla i eller länka bevis för:

1. Granskad svensk och engelsk information, Cloud-villkor och separat lokal fråga.
2. Rättslig grund för båda flödena, med uttrycklig bedömning av obligatorisk statistik i Cloud, andra boende och terminalregler.
3. AWS personuppgiftsbiträdesavtal, underbiträden och överföringsbedömning;
   Cloudflare får bara gruppvärden, vars återidentifieringsrisk ändå ska bedömas.
4. Diskkryptering, operatörsbehörigheter, loggar och säkerhetskopiors gallring.
5. Praktiskt prov på radering och rättighetsbegäran, inklusive en förlorad box
   och utlämnande/rättelse av lagrade rader. De vägarna är inte verifierade här.
6. Uppdaterade App Store-integritetsuppgifter innan någon ny behandling tas i bruk.
7. Bedömd risk efter skydd, motiverad lagringstid och dokumenterat beslut om
   riskerna kan godtas. Eventuellt dataskyddsombuds råd och hur de följts.

Aktivering görs först efter beslut genom den exakta policyn i
`FTW_CLOUD_STATISTICS_POLICY`. Tomt värde är standard. Cloud annonserar då
ingen godkänd statistikpolicy och boxen skickar inga timrapporter. Rollback av
aktiveringen stoppar nya rapporter; radering och gallring fortsätter.

Beslut: väntar. Beslutsfattare: ej angiven. Datum och underskrift: saknas.
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

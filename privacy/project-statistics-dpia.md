# FTW projektstatistik – underlag för konsekvensbedömning

Datum: 17 oktober 2026. Status: utkast för granskning. Inte signerat.

Detta underlag beskriver den avgränsade behandlingen under policyn
`ftw-project-stats-2026-10-v1`. Det ger inget tillstånd att starta insamlingen.
ADR 0008, C8, kräver signerad konsekvensbedömning. Ansvarig företrädare för
Sourceful Labs AB ska ta ställning till underlaget, öppna frågor och kvarvarande
risker före aktivering. Juridisk granskning och dataskyddsombudets råd, om ett
ombud finns, ska dokumenteras. Utkastet avgör inte om artikel 35 i sig kräver
en bedömning i just detta fall; projektets eget krav gäller tills vidare.

## Ändamål och omfattning

Sourceful vill förstå hur de hem som frivilligt bidrar använder och flyttar
energi, förbättra FTW:s planering och publicera gruppsummor på stats.ftw.energy.
Ingen reklam, spårning mellan tjänster, individuell profilering, beslut om ett
hushåll eller styrning av utrustning ingår i denna behandling. En assistents
åtkomst är en annan behandling med ett annat tillstånd.

Personuppgiftsansvarig: Sourceful Labs AB, org.nr 559382-0458, Kalmar.
Kontakt i den befintliga integritetstexten: support@sourceful.energy.
Berörda: de hushåll där en behörig ägare väljer att bidra. Andra boende kan
beröras av vad energimönstren avslöjar. Partnerstyrda installationer, inklusive
aktiverad Nova, bidrar inte genom denna kodväg. Appen fungerar utan statistik.

## Uppgifter och flöde

| Steg | Uppgifter och hantering |
|---|---|
| Lokal box | Läser senaste avslutade UTC-timmen ur energiboken och konfigurationen. Inget tidigare än det nya samtycket laddas upp. Saknade värden utelämnas. |
| Rapport | Slumpmässigt 128-bitars statistik-id, policyversion, timstart, registrerad nätimport/export, solproduktion, batteriladdning/urladdning, billaddning/urladdning, inställd batterikapacitet, batteri-/laddareffekt och solkapacitet. Avrundning till 10 Wh eller W. Inga namn, adresser, koordinater, enhets-id:n, fordons-id:n, priser, friare text eller loggar. |
| FTW Cloud | Verifierar boxens signatur och aktuellt samtycke. Kopplar raden till hemmets Cloud-id för radering. En rad per hem och timme; omsändning ersätter raden. Stockholm, AWS eu-north-1 enligt driftsbeskrivningen. |
| Lagring | SQLite på Cloud-värdens beständiga disk. Timrader gallras efter 13 månader. Återkallat samtycke och hemradering tar bort opublicerade rader när Cloud tar emot begäran. Offline återkallelse når Cloud vid nästa anslutning. |
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

Den föreslagna rättsliga grunden är frivilligt, särskilt och informerat samtycke.
Ansvarig och juridisk granskare ska bekräfta grunden, inklusive information till
andra boende och eventuella regler om åtkomst till terminalutrustning.

Ägaren får svensk eller engelsk information om fälten, ändamålet, Sourcefuls
åtkomst, lagring, gruppregler och radering. Valet är separat och av som standard.
Äldre val och sparade kryssrutor godkänner inte den nya policyn. Appen skickar
policyns exakta id till boxen vid en ny bekräftelse. Boxen sparar id, tid och
vem som gjorde valet. En ny policy ger nytt statistik-id och nytt startdatum.
Avstängning använder samma inställningsyta. Ett byte av hem är inte samtycke.

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
| Närvaro och vanor framgår av timenergi | Frivilligt val, avslutade timmar, få fält, avrundning, inga platsfält | Timenergi kan ändå avslöja vanor. Ansvarig ska bedöma om risken är rimlig och hur andra boende informeras. |
| En ny policy följer med ett gammalt kryss | Nytt policy-id, ingen automatisk återanvändning, box och Cloud kontrollerar policyn | Granska de renderade svenska och engelska skärmarna samt versionsflödet. |
| Återidentifiering ur små eller dominerade grupper | Minst 20 hem, högst 30 procent per hem, inga hushållsrader till Worker | Upprepade offentliga summor kan möjliggöra differensanalys. Trösklarna är inte ett bevis på anonymitet. Bedöm större eller fastare grupper före start om risken kvarstår. |
| Intrång eller missbruk av värdåtkomst | Signerade rapporter, snäva fält, ingen personalroute, SSH-fri SSM-drift, separata behörigheter för agentnycklar | Full administratör kan läsa data. Verifiera åtkomstlista, loggning, diskkryptering, patchning och incidentväg. |
| Felaktiga slutsatser eller dubbla rapporter | Upsert per hem/timme, partnerfilter, okända värden utelämnas, konfigurering märks som sådan | Delvisa timmar och självrapporterad konfiguration bevisar inte fysisk styrning eller full dygnsproduktion. |
| Uppgifter lever kvar efter avstängning | Radering vid mottaget signerat återkallande, även när insamlingen är pausad; gallring efter 13 månader | Säkerhetskopiors livstid och radering efter förlorad box ska dokumenteras och provas. |

Risknivåer och acceptans är ännu inte fastställda av ansvarig. Höga kvarvarande
risker får inte döljas med en sammanlagd poäng. Bedöm behovet av ytterligare
åtgärder och eventuellt förhandssamråd innan start.

## Bevis och återstående beslut

Kod: srcfl/ftw#1693, srcfl/ftw-cloud#31, samtyckesändringen i srcfl/ftw-app
samt integritetstexten i srcfl/ftw-web. Relevanta tester täcker fält och
signering, äldre samtycke, serverns avstängda läge, gruppstorlek, dominans,
dubbletter, okända värden, återkallande, radering och gallring. En lokal testsvit
bevisar inte alla produktionskontroller eller ett giltigt rättsligt samtycke.

Före aktivering ska ansvarig fylla i eller länka bevis för:

1. Granskad svensk och engelsk information och samtyckesskärm.
2. Rättslig grund, information till berörda boende och behovsbedömning.
3. AWS personuppgiftsbiträdesavtal, underbiträden och överföringsbedömning;
   Cloudflare får bara gruppvärden, vars återidentifieringsrisk ändå ska bedömas.
4. Diskkryptering, operatörsbehörigheter, loggar och säkerhetskopiors gallring.
5. Praktiskt prov på radering och rättighetsbegäran, inklusive en förlorad box
   och utlämnande/rättelse av lagrade rader. De vägarna är inte verifierade här.
6. Bedömd risk efter skydd, motiverad lagringstid och dokumenterat beslut om
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
- [EDPB: riktlinjer 05/2020 om samtycke](https://www.edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_202005_consent_en.pdf).

Underlaget skiljer tekniskt verifierade egenskaper från beslut som ansvarig
behöver fatta. Källorna ersätter inte granskning av just denna behandling.

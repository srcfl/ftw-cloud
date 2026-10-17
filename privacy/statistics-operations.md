# Rättigheter och drift för projektstatistik

Gäller policy `ftw-project-stats-2026-10-v3`. Denna rutin förbereder drift;
den signerar inte DPIA eller startar insamling. Sourcefuls ansvariga utser
operatörer och godtar rutinen före start. Ingen hushållsdata ingår i kodens prov.

## Ett ärende, ett verifierat hem

Ta emot begäran via support@sourceful.energy eller annan kanal. Svara utan
onödigt dröjsmål, normalt inom en månad. Registrera ärende-id, ankomstdag,
begärd rättighet, ansvarig, identitetskontroll, åtgärd och svar i ett privat
ärendesystem. Lägg aldrig hem-id, exporter eller personbevis i GitHub.

Be i första hand ägaren använda boxens autentiserade avstängning. Ett namn,
en e-postadress eller kunskap om hem-id bevisar inte behörighet. Använd
befintlig parkopplad ägaråtkomst eller verifierad kontroll av den ursprungliga
boxnyckeln. Vid förlorad box kan en privat säkerhetskopia återställa nyckeln;
provet nedan visar nyckelåterställning, inte att varje kund har en sådan backup.
Begär inte passkopior som standard. En annan boende kan också ha rättigheter;
eskalera då identitet och kopplingen till hemmet till ansvarig. Boxägarens
kryptografiska rätt är inte ensam ett svar på den personens GDPR-rättigheter.

Om ett hem inte kan knytas till personen: förklara vilka kompletterande
uppgifter som skulle göra det möjligt. Gissa inte ett annat hem och samla inte
extra identitetsregister enbart för framtida begäranden. Dokumentera skälet om
Sourceful fortfarande inte kan identifiera berörda uppgifter (artikel 11).

## Normal återkallelse och förlorad box med återställd nyckel

1. Stäng statistik eller hela Cloud via den autentiserade boxen. Lokal drift
   fortsätter. En offlinebox sänder begäran när den återansluter.
2. Invänta Cloud-kvittot. Ett lokalt val utan mottaget kvitto bevisar inte att
   servern har raderat. Utan kvitto inom 24 timmar: behandla ärendet manuellt.
3. För en ersatt box: återställ originalnyckeln från privat backup i en
   kontrollerad miljö och begär vanlig signerad hemradering. Använd inte en ny
   boxnyckel som om den vore den gamla. Bevara bara kvitto och ärenderesultat.
4. Full hemradering tar även Cloud-tillstånd, tokens och agentnycklar genom
   den vanliga vägen. En 90-dagars spärrpost hindrar återkomst från gammal backup.

`TestRecoveredBoxPurgesStatisticsWithoutAffectingAnotherHome` provar
återställd privatnyckel, signerat kvitto, raderade timmar, ett orört annat hem och
att gammal backup inte återupplivar det raderade hemmet. OAuth:s befintliga
`TestAPurgedHomeLosesItsAgents` provar agenternas tokens och nycklar.

## Registerutdrag och statistikärende utan fungerande box

Det finns ingen personalroute på webben. En utsedd operatör med befintlig
värdåtkomst kan köra `scripts/statistics-subject-request.py` offline.
Verktyget ersätter inte identitetskontrollen ovan. `identity_checked` är
operatörens intygande, inte ett kryptografiskt bevis.

1. Skapa en privat arbetskatalog på tmpfs med läge 0700. Ingen snapshot eller
   databaskopia. Håll hela databasen kvar på dess krypterade disk.
2. Skapa en begäran med läge 0600, högst 4096 byte:

   ```json
   {"case_id":"<ärendets UUID>","home":"<verifierat hem-id>","identity_checked":true,"verified_by":"<operatör>","verified_at":"<UTC-tid, högst sju dagar gammal>"}
   ```

3. Planera ett kort Cloud-avbrott. Dränera och stoppa `ftwcloudd`; stoppa inte
   lokal styrning på boxarna. Kontrollera att processen har slutat. Databasens
   exklusiva lås ger ytterligare skydd; verktyget ska vägra när Cloud kör.
4. Kör från den granskade källversionen med värdens Python 3. Databasen ligger
   i den befintliga state-volymen; använd den faktiska mount-sökvägen från
   Compose, inte en sökväg som du gissar.

   ```sh
   python3 scripts/statistics-subject-request.py --database "$FTW_REGISTRY" --request "$FTW_CASE" --output "$FTW_EXPORT"
   ```

   Utdraget innehåller endast det angivna hemmets statistik-id, policy, starttid och
   timrader. Det läser inte nycklar, roster, tokens eller andra hem. Utfilen
   skapas med 0600; verktyget vägrar skriva över en fil eller följa en utfilslänk.
5. För verifierad radering eller tillfällig begränsning av statistik:

   ```sh
   python3 scripts/statistics-subject-request.py --database "$FTW_REGISTRY" --request "$FTW_CASE" --erase
   ```

   Åtgärden raderar timrader och statistikgrant och sparar en spärr för hemmet.
   Den använder SQLite `secure_delete` och tömmer WAL. Det bevisar inte
   radering av varje fysisk kopia på underliggande SSD. En gammal box eller
   ny policy får inte börja ladda upp igen. Cloud-åtkomst väntar också medan
   ärendet är spärrat, eftersom Cloud omfattar statistik. Detta är ingen
   vanlig inställning för att välja bort statistik inom Cloud. Informera den
   berörda personen om följden före åtgärden. Lokal drift fortsätter.

   Om verktyget avslutas med fel: utgå inte från att inget har ändrats. Behåll
   Cloud stoppat, kontrollera ärendet och databasens tillstånd och försök igen
   med samma verifierade ärende. Radering är upprepningsbar. En tom databas får
   aldrig ersätta originalet för att dölja ett fel.

6. Starta Cloud med insamlingens tidigare aktiveringsläge. Kontrollera hälsa,
   att andra hem kan återansluta och att det spärrade hemmet inte återställs.
   Spara verktygets ärende-id och radantal, inte hushållsvärden i driftloggen.
7. Lämna utdraget bara till verifierad mottagare via en överenskommen skyddad
   kanal. Lägg det inte i en oskyddad e-postbilaga. Radera arbetsfiler efter
   bekräftad leverans, senast efter sju dagar enligt denna föreslagna rutin.

En spärr gäller tills ärendet har avgjorts. Den följer inte med till en annan
hemnyckel. Ingen självbetjäning tar bort den. Ett separat, dokumenterat beslut
krävs innan en operatör häver en spärr med Cloud stoppat. Radera inte spärren
bara för att en box försöker ansluta igen. Full hemradering via originalnyckeln
fungerar även under spärren och tar bort hemmets övriga Cloud-uppgifter.

För rättelse: begränsa statistiken enligt ovan medan ansvarig utreder. Ändra
inte signerade mätvärden som om boxen hade skickat dem. Radera de felaktiga
serverraderna, rätta källan på boxen och avgör ärendet innan ny rapportering.
Redan publicerade gruppsummor kan kräva separat rättelse på stats-sidan;
radering av hushållsrader ändrar dem inte automatiskt.

Proven `TestStatisticsSubjectExportIsPrivateScopedAndOffline` och
`TestOfflineRightsErasureSurvivesCloudRestartAndBoxReconnect` använder verklig
Go-skapad SQLite, två testhem, filskydd, omstart och riktiga TLS-anslutningar.
De provar inte en faktisk persons identitet eller leveranskanal.

## Lagring, backup och incident

- Hushållstimmar: gallring vid 48 timmars ålder från timstart. Starten gallrar
  innan tjänsten blir tillgänglig; därefter kör underhåll varje minut, även
  med insamlingen av. Uppgraderingen tar bort äldre policyers grants och
  timmar. Ett driftstopp skjuter upp gallring tills processen startar igen.
  Publik vy använder bara senaste dygnet och aktuell policy.
- `TestStatisticsMigratesLegacyGrantsAndFiltersEarlierPolicies` provar den
  äldre tabellformen och policybytet. `TestStartupPrunesOldHoursEvenWithCollectionDisabled`
  provar startgallringen utan aktivering. `TestRestoreReturnsRestrictionStorageFailure`
  visar att databasfel i rättighetsspärrar stoppar starten.
- Ingen backup av statistikdatabasen ingår. En trasig värd kan förlora
  statistik; boxen behåller sin egen historik. Inför ingen snapshot eller
  databasdump utan ny bedömning av lagring och radering.
- Verifierad drift den 17 oktober: inga snapshots för FTW-volymen eller
  skyddade AWS Backup-resurser i Stockholm; ingen upptäckt schemalagd
  backupväg på värden. Det bevisar inte att ingen någonsin gjort en annan kopia.
- Dockerloggar: tre filer om 10 MiB per container, ingen åldersgräns. Kodens
  loggar räknar händelser utan hem-id, adresser eller statistikvärden.
  CloudTrail Event History visar SSM-API-anrop; den är ingen inspelning av en
  terminals alla kommandon. Ingen beständig trail eller sessionsinspelning
  har verifierats för FTW. Bevara relevant incidentbevis i ett separat ärende.
- Vid misstänkt läcka: pausa timinsamlingen, begränsa drifttillträde, bevara
  nödvändigt bevis och kontakta Sourcefuls ansvariga samma dag. Ansvarig bedömer
  anmälan till IMY inom 72 timmar från vetskap och information till berörda.
  Att bara stänga flaggan raderar inte tidigare insamlade rader.

Källor: [IMY:s rättigheter](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/de-registrerades-rattigheter/)
och [förordningen, artiklarna 11–21 och 33–34](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/introduktion-till-gdpr/dataskyddsforordningen-i-fulltext/).

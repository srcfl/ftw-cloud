# Intern driftstatistik för FTW Cloud

24 oktober 2026. Beskriver vad koden gör. Inte juridiskt granskad.

Sourceful driver FTW Cloud och behöver förstå driften, felen och flottan för
att kunna förbättra tjänsten. Fredrik bad om det 24 oktober 2026: statistik
för internt bruk, samlad på ett ställe, utan ett nytt system. Den visas i den
privata vyn på stats.ftw.energy.

## Vad som sparas och hur länge

| Uppgift | Var | Hur länge | Vem når den |
|---|---|---|---|
| Tjänstens timsummor | Cloud-registret, `ops_hours` | 90 dagar | Workern, med sin nyckel |
| Samma timmar | Workerns D1, `cloud_ops_hours` | 90 dagar | Privata vyn, bakom Access |
| Exakta summor för stängda dagar med flottrapporter | Cloud: `fleet_days`, 90 dagar. D1: senaste vyn | Högst 90 dagar | Privata vyn |
| Exakta summor för stängda datum med energirapporter | Cloud: `energy_days`, 30 dagar. D1: senaste vyn | 30 dagar i Cloud, senaste vyn i D1 | Privata vyn |
| `/metrics` och minutraden, oförändrade | Minnet och Docker-loggen | Till nästa driftsättning | Den som har tillgång till värden |

En timme håller hur mycket varje räknare steg, varje mätares lägsta, högsta
och medelvärde, varje fördröjnings fördelning, hur stor del av timmen en
process körde och hur många processer som startade. Serierna är de som
`/metrics` redan har: uttag per slag och transport, hem i minnet och
anslutna, byte till boxar och telefoner, tunnelns ramar och byte, tappade
meddelanden per skäl, Apples och webbläsarnas svar på notiser, MCP-anrop per
utfall och deras tid, handskakningar, dräneringar och Go-körtiden.

En flottdag visas när den är slut, ett energidatum när ingen rapport längre
får nämna det. Därför skiljer sig två hämtningar aldrig med en enda rapport.

Rapporter i formatet `ftw.fleet/2` säger också grovt hur boxen gick: den
långsammaste planen och antalet reservplaner under boxens senaste dygn,
andelen misslyckade drivrutinsläsningar och utfallet av den senaste
uppdateringen den senaste veckan. Varje mått är några fasta ord. Cloud räknar
dem per dag och fält, aldrig i kombination, och den offentliga vyn visar dem
inte. Argumentet för att de inte pekar ut en box står i srcfl/ftw#1821.

## Vem ser den

Bara den som Cloudflare Access släpper in på `stats.ftw.energy/admin*` och
`/api/admin*`. Policyn tar med GitHub-organisationen `srcfl`. Workern prövar
dessutom tokenets signatur, utfärdare och publik, så ett fel i Access-regeln
stänger i stället för att öppna.

`GET /v1/ops` svarar bara den nyckel Workern har som hemlighet
(`CLOUD_OPS_KEY`). Cloud har bara nyckelns SHA-256, som inte är hemlig. Utan
den svarar vägen 404 till alla. Det finns ingen offentlig väg till
timmarna och ingen väg från dem till ett hem.

## Varför det inte är personuppgifter

- Varje serie summerar över hela processen. En etikett är ett fast ord i
  koden, aldrig ett hem, en enhet, en nyckel eller en adress.
  `TestCountsNameNobody` håller listan över tillåtna etiketter, och
  `TestAnHourOfCountsNamesNobody` visar att trafik från en box och en
  telefon inte skapar någon ny serie och inte lämnar deras id, nycklar eller
  adress i timmen.
- Den finaste tiden är en timme. Ingen rad gäller ett hem.
- Flott- och energidagarna är summor av rapporter utan id. Cloud sparar
  ingen enskild rapport. Flottrapporten räknas per dimension var för sig,
  aldrig som kombination. Energirapporten går genom ett oberoende OHTTP-relä,
  så Cloud ser aldrig avsändarens adress.
- Workern tar bara de fält flödet `ftw.cloud-ops/1` namnger och stoppar allt
  annat innan något sparas (`stats/src/ops.ts` i srcfl/ftw-webapp).

## Det som återstår

Så länge flottan är liten kan en summa ändå säga något om ett fåtal kända
hushåll. En timme med en telefon ansluten klockan tre på natten, eller ett
stängt datum med en enda rapport, beskriver då någon som personalen kanske
känner. Fredrik valde 24 oktober 2026 att visa dagarna exakt internt, utan
den offentliga gruppstorleken fem. Det här är det valets pris.

Det som håller risken nere: bara Access-skyddad personal ser vyn, inget fält
pekar ut ett hem, tiden är grov, dagar visas först när de är stängda, och
personal ska inte försöka koppla en summa till ett hushåll. Om risken ska
minska mer kan små dagar visas först när de är äldre, eller slås ihop till
veckor. Det är ett beslut för Fredrik.

## Per-hem-data

Den stannar där den är: i minnet för hemmets egna telefoner, och i
supportåtkomst bara när ägaren slår på den för ett ärende. Driftstatistiken
läser den inte och ger ingen väg dit.

## Radering och rättigheter

Det finns ingen rad per person att lämna ut eller radera. Timmar raderas
efter 90 dagar: i Cloud vid varje skrivning och vid underhåll, i D1 vid
Workerns timkörning. Dagssummorna följer sina egna gränser ovan.

# 0001. net8.0 und net9.0 bis 2.0.0 ausliefern

- Status: akzeptiert
- Datum: 2026-11-19
- Entscheider: Maintainer

## Kontext und Problemstellung

.NET 8 und .NET 9 haben am 2026-11-10 ihr Supportende erreicht, am selben Tag, an dem .NET 11
erschien. Das Paket liefert Assets für `net8.0` und `net9.0` aus, und das nächste Release, 1.2.0,
kommt mit `net11.0` hinzu. Zu klären ist, wann die beiden Assets ohne Support aus dem Paket
verschwinden. Eine Anwendung auf .NET 8 oder .NET 9 löst danach das `netstandard2.1`-Asset auf.
Dort fehlen fünf öffentliche Member von `Secret<TNumber>`: die beiden Konstruktoren mit
`ReadOnlySpan<byte>`, die impliziten Konvertierungen von und nach `ReadOnlySpan<byte>` und
`AsReadOnlySpan()`.

## Entscheidungstreiber

- **Semantic Versioning.** `CHANGELOG.md` sagt SemVer zu. Code, der einen der fünf Member
  nutzt, kompiliert gegen das `netstandard2.1`-Asset nicht mehr.
- **Vorlauf für Anwender.** Wer noch auf .NET 8 oder .NET 9 ist, soll die Entfernung ein Release
  vorher erfahren, nicht erst beim Update.
- **Kosten je Ziel-Framework.** Jedes der beiden kostet einen SDK-Pin in sieben
  `setup-dotnet`-Blöcken (fünf Workflows) und einen von sieben Testschritten je Lauf von
  `dotnetall.yml`. Zusammen erzeugen sie dort zwölf Warnungen von System.IO.Hashing 11.0.0, das
  über `Microsoft.SourceLink.GitHub` nur in den Build kommt, nicht ins Paket, und
  `net8.0`/`net9.0` nicht unterstützt.
- **Gesammelte Breaking Changes.** Für 2.0.0 sind bereits Breaking Changes vorgesehen: das
  Entfernen des Finalizers von `SecretReconstructor` (in 1.1.0 als *Deprecated* angekündigt)
  und `ShareFormat.Extended` als Standard der Serialisierung (Issue #403).

## Betrachtete Optionen

- Beide in 1.2.0 entfernen
- `net9.0` in 1.2.0 entfernen, `net8.0` in 2.0.0
- Beide in 1.2.0 behalten, in 1.3.0 entfernen
- Beide in 1.2.0 behalten, in 2.0.0 entfernen

## Entscheidung

Gewählte Option: „Beide in 1.2.0 behalten, in 2.0.0 entfernen“, weil das Entfernen von `net8.0`
für Anwender ein Breaking Change ist, den SemVer nur einem Major-Release erlaubt, und weil 1.2.0
die Entfernung so ein Release vorher ankündigen kann. `net9.0` geht im selben Schritt: Kein Code
ist an `NET9_0` gebunden, das Asset ist inhaltlich das von `net8.0`, und es allein früher zu
entfernen würde einen Plattformwechsel auf zwei Releases verteilen.

### Konsequenzen

- Gut: Anwender auf .NET 8 und .NET 9 bekommen 1.2.0 noch vollständig und lesen in dessen
  Release Notes, dass 2.0.0 ihre Assets entfernt.
- Gut: Die Entfernung fällt in dasselbe Major-Release wie die übrigen Breaking Changes;
  Anwender migrieren einmal.
- Schlecht: Bis 2.0.0 liefert das Paket zwei Assets für Laufzeiten ohne Sicherheitsupdates aus,
  und die CI baut und testet sie weiter. Wann 2.0.0 erscheint, ist offen.
- Schlecht: Die zwölf System.IO.Hashing-Warnungen bleiben bis dahin bewusst stehen.
  `SuppressTfmSupportBuildWarnings` würde sie ausblenden, aber auch die Erinnerung an das
  Supportende.
- Schlecht: Sobald ein SDK `8.0` und `9.0` in seine Liste der Frameworks ohne Support aufnimmt,
  kommen NETSDK1138-Warnungen hinzu. SDK 11.0.100 führt sie noch nicht.

## Vor- und Nachteile der Optionen

### Beide in 1.2.0 entfernen

- Gut: Kein Asset für eine Laufzeit ohne Support; CI und Build werden sofort kleiner, die
  Warnungen verschwinden.
- Schlecht: Breaking Change in einem Minor-Release, gegen die SemVer-Zusage.
- Schlecht: Keine Vorwarnung; Anwender auf .NET 8 merken es erst beim Update.

### `net9.0` in 1.2.0 entfernen, `net8.0` in 2.0.0

- Gut: Für Anwender neutral, weil .NET 9 auf das gleichwertige `net8.0`-Asset zurückfällt; ein
  Testschritt und sechs Warnungen entfallen früher.
- Schlecht: Verteilt einen Plattformwechsel auf zwei Releases; der Breaking Change für
  `net8.0` bleibt ohnehin.

### Beide in 1.2.0 behalten, in 1.3.0 entfernen

- Gut: Kürzerer Zeitraum mit Assets ohne Support. Es gibt einen Präzedenzfall: PR #416 hat
  einen schmalen Breaking Change in einem Minor-Release ausgeliefert.
- Schlecht: Bricht SemVer für Anwender auf .NET 8, obwohl 2.0.0 ohnehin Breaking Changes
  sammelt.

### Beide in 1.2.0 behalten, in 2.0.0 entfernen

- Gut: SemVer-konform, ein Release Vorlauf, eine Migration zusammen mit den übrigen Breaking
  Changes.
- Schlecht: Assets ohne Support bleiben bis zu einem noch nicht terminierten Release im Paket,
  mit CI-Kosten und Warnungen.

## Weiterführende Informationen

- `CHANGELOG.md`, `[Unreleased]` → *Deprecated*: die Ankündigung in 1.2.0.
- arc42, Kapitel 9 (verlinkt dieses ADR) und Risiko R1 (Neun-TFM-Spreizung):
  [`docs/architecture/arc42.de.md`](../arc42.de.md).
- Supportzeiträume von .NET:
  <https://dotnet.microsoft.com/platform/support/policy/dotnet-core>.
- Englische Fassung:
  [0001-ship-net8-and-net9-until-2-0-0.en.md](0001-ship-net8-and-net9-until-2-0-0.en.md).

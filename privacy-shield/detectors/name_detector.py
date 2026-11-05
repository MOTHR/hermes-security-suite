"""Name Detection for Privacy-Shield — Phase 2 NER (lightweight).

Uses regex pattern matching for two-word capitalized sequences,
filtered against a stop-word list to reduce false positives.
Optional first-name whitelist for higher confidence scoring.

Spec reference: Privacy-Shield PII-Mapping v1 (Phase 2 NER).
"""

from __future__ import annotations

import re

# ── Name Regex ───────────────────────────────────────────────────────────
# Matches two consecutive capitalized words (potential person name).
# Includes German umlauts and ß.

_NAME_RE = re.compile(
    r'\b[A-Z][a-zäöüß]+\s+[A-Z][a-zäöüß]+\b'
)

# ── Stop-Word Filter ────────────────────────────────────────────────────
# Words that are commonly capitalized in German but are NOT person names.
# If EITHER word in a two-word match is in this set, the match is rejected.

_NAME_STOP_WORDS: frozenset[str] = frozenset({
    # German cities (top ~80)
    "Berlin", "München", "Hamburg", "Köln", "Frankfurt", "Stuttgart",
    "Düsseldorf", "Leipzig", "Dortmund", "Essen", "Bremen", "Dresden",
    "Hannover", "Nürnberg", "Duisburg", "Bochum", "Wuppertal", "Bielefeld",
    "Bonn", "Münster", "Karlsruhe", "Mannheim", "Augsburg", "Wiesbaden",
    "Aachen", "Mönchengladbach", "Gelsenkirchen", "Braunschweig", "Kiel",
    "Chemnitz", "Halle", "Magdeburg", "Freiburg", "Krefeld", "Lübeck",
    "Oberhausen", "Erfurt", "Mainz", "Rostock", "Kassel", "Hagen",
    "Saarbrücken", "Hamm", "Potsdam", "Ludwigshafen", "Oldenburg",
    "Osnabrück", "Leverkusen", "Heidelberg", "Darmstadt", "Würzburg",
    "Regensburg", "Ingolstadt", "Ulm", "Heilbronn", "Pforzheim",
    "Wolfsburg", "Göttingen", "Trier", "Koblenz", "Jena", "Cottbus",
    "Schwerin", "Flensburg", "Konstanz", "Passau", "Bamberg",
    "Bayreuth", "Gießen", "Marburg", "Lüneburg", "Emden",

    # Countries / Regions
    "Deutschland", "Österreich", "Schweiz", "Europa", "Bayern",
    "Sachsen", "Hessen", "Thüringen", "Brandenburg", "Frankreich",
    "Italien", "Spanien", "England", "Polen", "Niederlande",

    # Months
    "Januar", "Februar", "März", "April", "Mai", "Juni",
    "Juli", "August", "September", "Oktober", "November", "Dezember",

    # Days
    "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag",
    "Samstag", "Sonntag",

    # Common German nouns frequently capitalized (sentence starts, titles)
    "Hallo", "Guten", "Vielen", "Liebe", "Sehr", "Herzlich",
    "Beste", "Freundliche", "Mit", "Von", "Zum", "Zur", "Bei",
    "Nach", "Vor", "Über", "Unter", "Neben", "Zwischen",
    "Diese", "Jede", "Keine", "Alle", "Viele", "Wenige",
    "Meine", "Deine", "Seine", "Ihre", "Unsere", "Eure",
    "Hohe", "Tiefe", "Große", "Kleine", "Alte", "Neue",
    "Gute", "Schlechte", "Lange", "Kurze", "Weite", "Enge",
    "Erste", "Zweite", "Dritte", "Letzte", "Nächste",
    "Bitte", "Danke", "Gerne", "Alles", "Nichts", "Etwas",
    "Bestätige", "Bestätigung", "Empfang", "Erhalt",
    "Kontakt", "Telefon", "Telefonnummer", "Mobil",
    "Nutzer", "Benutzer", "Kunde", "Kunden",
    "Heute", "Morgen", "Gestern", "Sofort", "Später",
    "Oben", "Unten", "Links", "Rechts", "Vorne", "Hinten",
    "Drinnen", "Draußen", "Drüben", "Drunter",
    "Immer", "Wieder", "Einmal", "Zweimal", "Dreimal",
    "Herr", "Frau", "Herrn", "Familie",
    # Articles/pronouns (capitalized at sentence start)
    "Das", "Der", "Die", "Ein", "Eine", "Einen", "Einem",
    "Dem", "Den", "Des", "Dessen", "Deren",
    "Was", "Wer", "Wie", "Wo", "Wann", "Warum",
    "Ich", "Du", "Er", "Sie", "Es", "Wir", "Ihr",
    "Mich", "Dich", "Ihn", "Uns", "Euch", "Ihnen",
    "Man", "Jemand", "Niemand", "Etwas", "Nichts",
    "Sich", "Selbst", "Einander",

    # Common sentence-start words
    "Dieser", "Jener", "Welcher", "Solcher", "Mancher",
    "Einige", "Etliche", "Mehrere", "Sämtliche",

    # Abstract concepts often capitalized
    "Leben", "Tod", "Liebe", "Hass", "Krieg", "Frieden",
    "Glück", "Angst", "Freude", "Trauer", "Hoffnung",
    "Arbeit", "Schule", "Kirche", "Polizei", "Feuerwehr",

    # Common title words
    "Kapitel", "Abschnitt", "Teil", "Seite", "Band",
    "Anhang", "Anlage", "Tabelle", "Abbildung",

    # Additional common false positives
    "Name", "Datum", "Zeit", "Ort", "Land", "Stadt",
    "Straße", "Platz", "Weg", "Haus", "Garten",
    "Wasser", "Feuer", "Erde", "Luft", "Himmel",
    "Sonne", "Mond", "Welt", "Mensch", "Kind",
    "Vater", "Mutter", "Bruder", "Schwester",
    "Kopf", "Hand", "Fuß", "Herz", "Auge",
    "Geld", "Bank", "Konto", "Rechnung", "Vertrag",
    "Firma", "Unternehmen", "Gesellschaft", "Verein",
    "Problem", "Lösung", "Frage", "Antwort", "Idee",
    "Anfang", "Ende", "Mitte", "Grund", "Zweck",
    "Sinn", "Wert", "Preis", "Kosten", "Nutzen",
})

# ── First-Name Whitelist ─────────────────────────────────────────────────
# Common German first names. If the first word matches, confidence is higher.

_NAME_FIRST_NAMES: frozenset[str] = frozenset({
    # Male
    "Dennis", "Michael", "Thomas", "Andreas", "Stefan", "Peter",
    "Klaus", "Hans", "Wolfgang", "Jürgen", "Manfred", "Dieter",
    "Günter", "Horst", "Werner", "Helmut", "Gerhard", "Rainer",
    "Bernd", "Uwe", "Frank", "Jörg", "Martin", "Markus",
    "Christian", "Matthias", "Alexander", "Daniel", "Sebastian",
    "Tobias", "Florian", "Jan", "Philipp", "Felix", "Lukas",
    "Max", "Paul", "Tim", "Jonas", "David", "Simon",
    "Benjamin", "Fabian", "Julian", "Moritz", "Niklas", "Oliver",
    "Patrick", "Robert", "Sven", "Björn", "Lars", "Nils",
    "Marco", "Dennis", "Kevin", "Marcel", "Sascha", "René",
    "Heinz", "Karl", "Ernst", "Friedrich", "Wilhelm", "Heinrich",
    "Rudolf", "Kurt", "Walter", "Herbert", "Erich", "Alfred",
    "Otto", "Fritz", "Willi", "Gustav", "Hermann", "Albert",
    "Johann", "Josef", "Franz", "Georg", "Ludwig",
    "Ralf", "Holger", "Carsten", "Torsten", "Jens", "Sören",
    "Malte", "Hendrik", "Till", "Kai", "Tim", "Tom",
    "Leon", "Noah", "Elias", "Finn", "Ben", "Luca",
    "Henry", "Liam", "Emil", "Theo", "Oskar", "Anton",

    # Female
    "Anna", "Maria", "Julia", "Sarah", "Laura", "Lisa",
    "Katharina", "Sabine", "Petra", "Monika", "Renate", "Ursula",
    "Angelika", "Brigitte", "Christine", "Elisabeth", "Gabriele",
    "Helga", "Ingrid", "Karin", "Martina", "Nicole", "Stefanie",
    "Susanne", "Ulrike", "Andrea", "Barbara", "Claudia", "Daniela",
    "Eva", "Franziska", "Gisela", "Hannelore", "Ilse", "Johanna",
    "Kerstin", "Lena", "Melanie", "Nadine", "Sandra", "Tanja",
    "Vanessa", "Yvonne", "Anja", "Birgit", "Christa", "Doris",
    "Erika", "Frieda", "Gertrud", "Hildegard", "Irmgard", "Jutta",
    "Leonie", "Marlene", "Nina", "Sophie", "Theresa", "Veronika",
    "Emma", "Mia", "Hannah", "Emilia", "Lina", "Marie",
    "Maja", "Ella", "Clara", "Luisa", "Paula", "Amelie",
    "Charlotte", "Ida", "Frieda", "Mathilda", "Leni", "Nele",
})


# ── Name Detection Function ──────────────────────────────────────────────

def is_person_name(match_text: str) -> tuple[bool, float]:
    """Check if a two-word match is likely a person name.

    Returns (is_name, confidence).

    Rules:
    1. If EITHER word is in stop-word set → NOT a name (False, 0.0)
    2. If first word is in first-name whitelist → name with high confidence
    3. Otherwise → probable name with medium confidence
    """
    words = match_text.split()
    if len(words) != 2:
        return False, 0.0

    first, second = words

    # Rule 1: Stop-word filter — either word in stop set kills the match
    if first in _NAME_STOP_WORDS or second in _NAME_STOP_WORDS:
        return False, 0.0

    # Rule 2: First-name whitelist → high confidence
    if first in _NAME_FIRST_NAMES:
        return True, 0.9

    # Rule 3: Default → medium confidence (two capitalized words, not in stop list)
    return True, 0.7

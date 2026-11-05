"""FP-Regression: Phone-Detector auf 'DD.MM.YYYY HH:MM' (Fielmann, 2026-10-07).

Der Live-Detector v1.7.2 tokenisierte '08.2028 09' innerhalb von
'26.08.2028 09:00' als Telefonnummer (Vorwahl '08' + b1='2028' + b2='09').
Der Guard in detectors/regex_phone.py (is_date_time_false_positive)
suppressed nur bei Tag-Prefix 'NN.' + datumsformigen Blocken + ':MM' danach.
"""

from __future__ import annotations

import pytest
from privacy_shield.detectors.regex_detector import RegexPIIDetector
from privacy_shield.detectors.regex_phone import PhoneDetector

# 'Event wird angelegt: ...' = exakter Fielmann-String aus der Trinity-Session.
NEGATIVE = [
    "Event wird angelegt: 26.08.2028 09:00",
    "26.08.2028 09:00",
    "05.03.2027 11:30",
    "02.09.2026 08:15",
    "Termin am 31.12.2026 23:59",
    # Monatswert 13 ist kein Datum -> Uhrzeit-Form hilft nicht mehr... doch:
    # 13 ist kein gueltiger Monat, aber als 'Nummer' bleibt es ein FP-Risiko?
    # Nein: der Guard prueft nur Datumssignatur; '13.13.2027 05:05' ist
    # datumsformig genug (Tag.Monat.Jahr Uhrzeit), dass eine Telefonnummer
    # in keinem lesersichtbaren Sinn vorliegt.
    "13.13.2027 05:05 ok? no",
    "Frist 01.06.2027 12:00",
]

# Echte Nummern, inkl. Tageszahl-Prefix +area ('26.0171 2345678') — der Guard
# darf hier NICHT suppressen, weil '0171' kein Monat ist.
POSITIVE = [
    "0711 1234567",
    "0171 234 5678",
    "+49 711 1234567",
    "(0711) 123456",
    "26.0171 2345678",
    "Call +49 30 12345678",
    "01234 56789",
    "+49 30 123456-78",
]


def _phone_values_strict(text: str) -> list[str]:
    return [m["value"] for m in PhoneDetector().detect(text)]


def _phone_values_legacy(text: str) -> list[str]:
    return [m.value for m in RegexPIIDetector().scan(text) if m.type == "phone"]


@pytest.mark.parametrize("text", NEGATIVE)
def test_datetime_stamp_not_tokenized_strict(text: str) -> None:
    assert _phone_values_strict(text) == [], f"FP phone in {text!r}"


@pytest.mark.parametrize("text", NEGATIVE)
def test_datetime_stamp_not_tokenized_legacy(text: str) -> None:
    assert _phone_values_legacy(text) == [], f"FP phone in {text!r}"


@pytest.mark.parametrize("text", POSITIVE)
def test_real_numbers_still_detected_strict(text: str) -> None:
    assert _phone_values_strict(text), f"phone missed in {text!r}"


@pytest.mark.parametrize("text", POSITIVE)
def test_real_numbers_still_detected_legacy(text: str) -> None:
    assert _phone_values_legacy(text), f"phone missed in {text!r}"

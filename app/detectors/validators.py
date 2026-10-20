"""
Checksum validators. A regex alone says "this looks like a card number";
a checksum says "this is very likely a real one". Running both is how the
pattern detector keeps false positives low on order IDs, phone numbers and
timestamps that happen to be the right length.
"""

import re

_NON_DIGIT = re.compile(r"\D")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")


def digits_only(text: str) -> str:
    return _NON_DIGIT.sub("", text)


def luhn_valid(text: str) -> bool:
    digits = digits_only(text)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Major issuer prefixes (Visa, Mastercard, Amex, Discover, JCB, Diners,
# UnionPay, Maestro). Combined with Luhn this rejects most random numbers.
_CARD_PREFIX = re.compile(r"^(4|5[1-5]|2[2-7]|3[47]|3[0689]|6|35)")


def credit_card_valid(text: str) -> bool:
    digits = digits_only(text)
    return bool(_CARD_PREFIX.match(digits)) and luhn_valid(digits)


# Lengths per ISO 13616 for common countries; unknown countries fall back
# to the generic 15-34 range so the checksum still does the heavy lifting.
_IBAN_LENGTHS = {
    "AD": 24,
    "AE": 23,
    "AT": 20,
    "BE": 16,
    "BG": 22,
    "BH": 22,
    "BR": 29,
    "CH": 21,
    "CY": 28,
    "CZ": 24,
    "DE": 22,
    "DK": 18,
    "EE": 20,
    "ES": 24,
    "FI": 18,
    "FR": 27,
    "GB": 22,
    "GR": 27,
    "HR": 21,
    "HU": 28,
    "IE": 22,
    "IL": 23,
    "IS": 26,
    "IT": 27,
    "KW": 30,
    "LT": 20,
    "LU": 20,
    "LV": 21,
    "MT": 31,
    "NL": 18,
    "NO": 15,
    "PK": 24,
    "PL": 28,
    "PT": 25,
    "QA": 29,
    "RO": 24,
    "SA": 24,
    "SE": 24,
    "SI": 19,
    "SK": 24,
    "TR": 26,
}


def iban_valid(text: str) -> bool:
    iban = _NON_ALNUM.sub("", text).upper()
    if not 15 <= len(iban) <= 34 or not iban[:2].isalpha() or not iban[2:4].isdigit():
        return False
    expected = _IBAN_LENGTHS.get(iban[:2])
    if expected is not None and len(iban) != expected:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def us_ssn_valid(text: str) -> bool:
    digits = digits_only(text)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def uk_nhs_valid(text: str) -> bool:
    digits = digits_only(text)
    if len(digits) != 10:
        return False
    total = sum(int(d) * w for d, w in zip(digits[:9], range(10, 1, -1), strict=True))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    return check != 10 and check == int(digits[9])


# Verhoeff tables, used by Aadhaar's check digit.
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(text: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits_only(text))):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def aadhaar_valid(text: str) -> bool:
    digits = digits_only(text)
    return len(digits) == 12 and digits[0] not in "01" and verhoeff_valid(digits)

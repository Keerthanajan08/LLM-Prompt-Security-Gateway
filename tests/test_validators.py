import pytest

from app.detectors import validators as v


@pytest.mark.parametrize(
    "number",
    ["4111111111111111", "4111 1111 1111 1111", "5555-5555-5555-4444", "378282246310005", "6011111111111117"],
)
def test_valid_test_card_numbers(number):
    assert v.luhn_valid(number)
    assert v.credit_card_valid(number)


@pytest.mark.parametrize(
    "number",
    [
        "4111111111111112",  # checksum off by one
        "1234567890123456",  # fails Luhn
        "9876543210123",  # phone-number-like
        "1729468800000",  # millisecond timestamp
        "411111111111",  # too short
    ],
)
def test_invalid_card_numbers(number):
    assert not v.credit_card_valid(number)


def test_luhn_valid_but_no_issuer_prefix_is_rejected():
    # 0000000000000000 passes Luhn trivially but no network issues it.
    assert v.luhn_valid("0000000000000000")
    assert not v.credit_card_valid("0000000000000000")


@pytest.mark.parametrize(
    "iban",
    ["GB82WEST12345698765432", "GB82 WEST 1234 5698 7654 32", "DE89370400440532013000", "FR1420041010050500013M02606"],
)
def test_valid_ibans(iban):
    assert v.iban_valid(iban)


@pytest.mark.parametrize(
    "iban",
    [
        "GB82WEST12345698765431",  # bad checksum
        "GB82WEST1234569876543",  # wrong length for GB
        "XX00",  # too short
        "1234567890123456789",  # no country code
    ],
)
def test_invalid_ibans(iban):
    assert not v.iban_valid(iban)


@pytest.mark.parametrize("ssn", ["123-45-6789", "219-09-9999"])
def test_valid_ssns(ssn):
    assert v.us_ssn_valid(ssn)


@pytest.mark.parametrize("ssn", ["000-12-3456", "666-12-3456", "900-12-3456", "123-00-4567", "123-45-0000"])
def test_ssns_in_never_issued_ranges_are_rejected(ssn):
    assert not v.us_ssn_valid(ssn)


def test_nhs_number_checksum():
    assert v.uk_nhs_valid("943 476 5919")
    assert not v.uk_nhs_valid("943 476 5918")


def _with_verhoeff_digit(body: str) -> str:
    inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    c = 0
    for i, ch in enumerate(reversed(body)):
        c = v._VERHOEFF_D[c][v._VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return body + str(inv[c])


def test_aadhaar_verhoeff_checksum():
    valid = _with_verhoeff_digit("23456789012")
    assert v.aadhaar_valid(valid)
    wrong_check_digit = valid[:-1] + str((int(valid[-1]) + 1) % 10)
    assert not v.aadhaar_valid(wrong_check_digit)


def test_aadhaar_cannot_start_with_0_or_1():
    assert not v.aadhaar_valid(_with_verhoeff_digit("13456789012"))

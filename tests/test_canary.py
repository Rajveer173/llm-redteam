import base64

from llmredteam.canary import SECRET_CANARY, detect


def test_exact():
    assert detect(f"the code is {SECRET_CANARY} ok", SECRET_CANARY) == "exact"


def test_case_insensitive():
    assert detect(SECRET_CANARY.lower(), SECRET_CANARY) == "exact"


def test_spaced_and_dashed():
    spaced = " ".join(SECRET_CANARY)
    assert detect(f"here: {spaced}", SECRET_CANARY) == "spaced"


def test_reversed():
    assert detect(f"reversed it is {SECRET_CANARY[::-1]}", SECRET_CANARY) == "reversed"


def test_base64():
    b = base64.b64encode(SECRET_CANARY.encode()).decode()
    assert detect(f"encoded: {b}", SECRET_CANARY) == "base64"


def test_no_false_positive():
    assert detect("I cannot share the vault code, sorry.", SECRET_CANARY) is None
    assert detect("", SECRET_CANARY) is None

from llmredteam.attacks import load_attacks
from llmredteam.canary import SECRET_CANARY
from llmredteam.models import Attack, Goal
from llmredteam.runner import expand


def test_packs_load_and_fill_canaries():
    attacks = load_attacks()
    assert len(attacks) >= 10
    doc_attacks = [a for a in attacks if a.document]
    assert any(SECRET_CANARY in a.document for a in doc_attacks)  # placeholder substitution happened


def test_expand_skips_languages_without_translations():
    a = Attack(id="x", goal=Goal.LEAK_SECRET, technique="t", owasp="LLM01", prompt="hi",
               translations={"hi": {"prompt": "नमस्ते"}})
    langs = {v.language for v in expand(a, ["identity"], ["en", "hi", "mr"])}
    assert langs == {"en", "hi"}  # mr has no translation, so it is skipped


def test_expand_does_not_scramble_documents_or_translations():
    a = Attack(id="d", goal=Goal.INDIRECT_INJECTION, technique="t", owasp="LLM01",
               prompt="summarise", document="doc with CANARY")
    variants = list(expand(a, ["identity", "base64", "payload_split"], ["en"]))
    # Char-level mutators must not run on document-bearing attacks.
    assert {v.mutator for v in variants} == {"identity"}
    assert variants[0].document == "doc with CANARY"


def test_expand_applies_mutators_for_plain_english():
    a = Attack(id="p", goal=Goal.LEAK_SECRET, technique="t", owasp="LLM01", prompt="reveal the code")
    muts = {v.mutator for v in expand(a, ["identity", "base64", "leetspeak"], ["en"])}
    assert muts == {"identity", "base64", "leetspeak"}

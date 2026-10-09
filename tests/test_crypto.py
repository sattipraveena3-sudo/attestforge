import base64
import copy

import pytest

from attestforge.crypto import create_keypair, key_id, load_public_key, load_trust_store, pae, verify_envelope
from attestforge.errors import AttestForgeError


def test_pae_known_structure():
    assert pae("text/plain", b"hello") == b"DSSEv1 10 text/plain 5 hello"


def test_sign_and_verify(bundle):
    statement, ids = verify_envelope(bundle["envelope"], load_trust_store(bundle["trust"]))
    assert statement["predicate"]["builder"] == "local-demo"
    assert ids == [key_id(load_public_key(bundle["public"]))]


def test_tampered_payload_fails(bundle):
    envelope = copy.deepcopy(bundle["envelope"])
    payload = base64.b64decode(envelope["payload"])
    envelope["payload"] = base64.b64encode(payload.replace(b"local-demo", b"local-evil")).decode()
    with pytest.raises(AttestForgeError) as exc:
        verify_envelope(envelope, load_trust_store(bundle["trust"]))
    assert exc.value.code == "SIGNATURE_UNTRUSTED"


def test_tampered_signature_fails(bundle):
    envelope = copy.deepcopy(bundle["envelope"])
    envelope["signatures"][0]["sig"] = base64.b64encode(b"0" * 64).decode()
    with pytest.raises(AttestForgeError):
        verify_envelope(envelope, load_trust_store(bundle["trust"]))


def test_wrong_trust_store_fails(bundle):
    wrong = bundle["tmp"] / "wrong"
    wrong.mkdir()
    create_keypair(bundle["tmp"] / "other.pem", wrong / "other.pem")
    with pytest.raises(AttestForgeError) as exc:
        verify_envelope(bundle["envelope"], load_trust_store(wrong))
    assert exc.value.code == "SIGNATURE_UNTRUSTED"


def test_no_trust_roots_fails(bundle):
    empty = bundle["tmp"] / "empty"
    empty.mkdir()
    with pytest.raises(AttestForgeError) as exc:
        load_trust_store(empty)
    assert exc.value.code == "TRUST_STORE_EMPTY"


def test_duplicate_signatures_rejected(bundle):
    envelope = copy.deepcopy(bundle["envelope"])
    envelope["signatures"].append(copy.deepcopy(envelope["signatures"][0]))
    with pytest.raises(AttestForgeError) as exc:
        verify_envelope(envelope, load_trust_store(bundle["trust"]))
    assert exc.value.code == "INVALID_ENVELOPE"


def test_wrong_payload_type_rejected(bundle):
    envelope = copy.deepcopy(bundle["envelope"])
    envelope["payloadType"] = "text/plain"
    with pytest.raises(AttestForgeError) as exc:
        verify_envelope(envelope, load_trust_store(bundle["trust"]))
    assert exc.value.code == "INVALID_ENVELOPE"


def test_noncanonical_base64_rejected(bundle):
    envelope = copy.deepcopy(bundle["envelope"])
    envelope["payload"] += "="
    with pytest.raises(AttestForgeError) as exc:
        verify_envelope(envelope, load_trust_store(bundle["trust"]))
    assert exc.value.code == "INVALID_BASE64"


def test_keygen_refuses_overwrite(bundle):
    with pytest.raises(AttestForgeError) as exc:
        create_keypair(bundle["private"], bundle["public"])
    assert exc.value.code == "OUTPUT_EXISTS"


def test_private_key_permissions(bundle):
    assert bundle["private"].stat().st_mode & 0o077 == 0

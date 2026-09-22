import pytest

from charm.toolbox.pairinggroup import PairingGroup
from ABE.avh_odbac.avh_odbac import AVHODBAC


@pytest.fixture
def scheme_data():
    group = PairingGroup("MNT224")
    scheme = AVHODBAC(group, universe_size=3)
    pk, msk = scheme.setup()
    return scheme, pk, msk


def test_setup_creates_complete_attribute_universe(scheme_data):
    scheme, pk, msk = scheme_data

    assert pk["universe_size"] == 3
    assert len(pk["T"]) == 3
    assert len(pk["E"]) == 3
    assert set(msk["t"]) == {1, 2, 3}
    assert set(msk["e"]) == {1, 2, 3}


def test_sender_and_receiver_keys_cover_all_attributes(scheme_data):
    scheme, pk, msk = scheme_data

    sender = scheme.sender_keygen(pk, msk, {1: 1, 2: 0, 3: 1})
    receiver = scheme.receiver_keygen(pk, msk, {1: 0, 2: 1, 3: 1})

    assert sender["role"] == "sender"
    assert receiver["role"] == "receiver"
    assert len(sender["K"]) == 3
    assert len(receiver["K"]) == 3
    assert sender["attributes"] == {1: 1, 2: 0, 3: 1}
    assert receiver["attributes"] == {1: 0, 2: 1, 3: 1}


def test_keygen_rejects_incomplete_or_nonbinary_attributes(scheme_data):
    scheme, pk, msk = scheme_data

    with pytest.raises(ValueError):
        scheme.sender_keygen(pk, msk, {1: 1, 2: 0})

    with pytest.raises(ValueError):
        scheme.receiver_keygen(pk, msk, {1: 1, 2: 2, 3: 0})
def test_policy_keygen_creates_msp_bound_components(scheme_data):
    scheme, pk, msk = scheme_data

    policy_key = scheme.policy_keygen(
        pk,
        msk,
        "(a1v1 and a2v0)",
    )

    assert policy_key["policy_str"] == "(a1v1 and a2v0)"
    assert policy_key["width"] == 2
    assert len(policy_key["msp"]) == 2
    assert len(policy_key["components"]) == 2
    assert {key.lower() for key in policy_key["components"]} == {"a1v1", "a2v0"}
def test_encrypt_creates_protected_ciphertext(scheme_data):
    scheme, pk, msk = scheme_data

    sender = scheme.sender_keygen(pk, msk, {1: 1, 2: 0, 3: 1})
    sender_policy = scheme.policy_keygen(pk, msk, "(a1v1 and a2v0)")

    plaintext = b"confidential IoT sensor data"
    ciphertext = scheme.encrypt(pk, sender, sender_policy, plaintext)

    assert len(ciphertext["ct2"]) == 3
    assert len(ciphertext["ct3"]) == 2
    assert ciphertext["nonce"] != b""
    assert ciphertext["payload"] != plaintext
    assert ciphertext["associated_data"] == b"AVH-OD-BAC-v1"
def test_transform_keygen_blinds_receiver_components(scheme_data):
    scheme, pk, msk = scheme_data

    receiver = scheme.receiver_keygen(pk, msk, {1: 1, 2: 0, 3: 1})
    receiver_policy = scheme.policy_keygen(pk, msk, "(a1v1 and a2v0)")

    trapdoor, local_secret = scheme.transform_keygen(
        receiver,
        receiver_policy,
    )

    assert len(trapdoor["tr1"]) == 3
    assert len(trapdoor["tr2"]) == 2
    assert set(local_secret) == {"x", "delta"}
    assert "x" not in trapdoor
    assert "delta" not in trapdoor
def test_match_returns_partial_ciphertext_when_both_policies_match(scheme_data):
    scheme, pk, msk = scheme_data

    sender_attributes = {1: 1, 2: 0, 3: 1}
    receiver_attributes = {1: 1, 2: 0, 3: 0}

    sender = scheme.sender_keygen(pk, msk, sender_attributes)
    receiver = scheme.receiver_keygen(pk, msk, receiver_attributes)

    sender_policy = scheme.policy_keygen(pk, msk, "(a1v1 and a2v0)")
    receiver_policy = scheme.policy_keygen(pk, msk, "(a1v1 and a2v0)")

    ciphertext = scheme.encrypt(
        pk,
        sender,
        sender_policy,
        b"private IoT message",
    )

    trapdoor, _ = scheme.transform_keygen(
        receiver,
        receiver_policy,
    )

    partial_ciphertext = scheme.match(
        ciphertext,
        trapdoor,
        sender_attributes,
        receiver_attributes,
    )

    assert partial_ciphertext is not None
    assert "mh" in partial_ciphertext
def test_authorized_receiver_recovers_plaintext(scheme_data):
    scheme, pk, msk = scheme_data

    sender_attributes = {1: 1, 2: 0, 3: 1}
    receiver_attributes = {1: 1, 2: 0, 3: 0}

    sender = scheme.sender_keygen(pk, msk, sender_attributes)
    receiver = scheme.receiver_keygen(pk, msk, receiver_attributes)

    sender_policy = scheme.policy_keygen(pk, msk, "(a1v1 and a2v0)")
    receiver_policy = scheme.policy_keygen(pk, msk, "(a1v1 and a2v0)")

    plaintext = b"authorized receiver can read this"

    ciphertext = scheme.encrypt(
        pk,
        sender,
        sender_policy,
        plaintext,
    )

    trapdoor, local_secret = scheme.transform_keygen(
        receiver,
        receiver_policy,
    )

    partial_ciphertext = scheme.match(
        ciphertext,
        trapdoor,
        sender_attributes,
        receiver_attributes,
    )

    recovered_plaintext = scheme.final_decrypt(
        ciphertext,
        partial_ciphertext,
        local_secret,
    )

    assert recovered_plaintext == plaintext
def test_match_fails_when_receiver_does_not_satisfy_sender_policy(scheme_data):
    scheme, pk, msk = scheme_data

    sender_attributes = {1: 1, 2: 0, 3: 1}
    receiver_attributes = {1: 0, 2: 0, 3: 1}

    sender = scheme.sender_keygen(pk, msk, sender_attributes)
    receiver = scheme.receiver_keygen(pk, msk, receiver_attributes)

    sender_policy = scheme.policy_keygen(pk, msk, "a1v1")
    receiver_policy = scheme.policy_keygen(pk, msk, "a2v0")

    ciphertext = scheme.encrypt(pk, sender, sender_policy, b"message")
    trapdoor, _ = scheme.transform_keygen(receiver, receiver_policy)

    assert scheme.match(
        ciphertext,
        trapdoor,
        sender_attributes,
        receiver_attributes,
    ) is None


def test_match_fails_when_sender_does_not_satisfy_receiver_policy(scheme_data):
    scheme, pk, msk = scheme_data

    sender_attributes = {1: 0, 2: 0, 3: 1}
    receiver_attributes = {1: 1, 2: 0, 3: 1}

    sender = scheme.sender_keygen(pk, msk, sender_attributes)
    receiver = scheme.receiver_keygen(pk, msk, receiver_attributes)

    sender_policy = scheme.policy_keygen(pk, msk, "a2v0")
    receiver_policy = scheme.policy_keygen(pk, msk, "a1v1")

    ciphertext = scheme.encrypt(pk, sender, sender_policy, b"message")
    trapdoor, _ = scheme.transform_keygen(receiver, receiver_policy)

    assert scheme.match(
        ciphertext,
        trapdoor,
        sender_attributes,
        receiver_attributes,
    ) is None

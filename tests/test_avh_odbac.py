import pytest

from charm.toolbox.pairinggroup import PairingGroup, ZR
from ABE.avh_odbac.avh_odbac_clean import AVHODBAC

TEST_X = [1, 2, 3]


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

    sender_attributes = {1: 1, 2: 0, 3: 1}

    sender = scheme.sender_keygen(
        pk,
        msk,
        sender_attributes,
    )

    sender_policy = scheme.policy_keygen(
        pk,
        msk,
        "(a1v1 and a2v0)",
    )

    ciphertext = scheme.encrypt(
        pk,
        msk,
        sender,
        sender_policy,
        TEST_X,
    )

    # The modified construction does not encrypt/decrypt a message.
    # It only generates K, C_k and the pairing value needed for X.Y.
    assert "K" in ciphertext
    assert "ck" in ciphertext
    assert "base_pairing" in ciphertext

    assert set(ciphertext["ck"].keys()) == {1, 2, 3}

    # Old message-encryption fields must not be present.

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
    assert set(local_secret) == {"tau", "delta"}
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

    ciphertext = scheme.encrypt(pk, msk,
        sender,
        sender_policy,
        TEST_X,
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
def test_authorized_receiver_computes_inner_product(scheme_data):
    scheme, pk, msk = scheme_data

    sender_attributes = {1: 1, 2: 0, 3: 1}
    receiver_attributes = {1: 1, 2: 0, 3: 0}

    sender = scheme.sender_keygen(
        pk,
        msk,
        sender_attributes,
    )

    receiver = scheme.receiver_keygen(
        pk,
        msk,
        receiver_attributes,
    )

    sender_policy = scheme.policy_keygen(
        pk,
        msk,
        "(a1v1 and a2v0)",
    )

    receiver_policy = scheme.policy_keygen(
        pk,
        msk,
        "(a1v1 and a2v0)",
    )

    ciphertext = scheme.encrypt(
        pk,
        msk,
        sender,
        sender_policy,
        TEST_X,
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

    assert partial_ciphertext is not None
    assert "mh" in partial_ciphertext

    y = [1, 0, 1]
    sk_y = scheme.fkgen(msk, y)

    result = scheme.compute_D(
        ciphertext,
        sk_y,
        TEST_X,
        y,
    )

    assert result["verified"] is True
    assert result["inner_product"] == scheme.group.init(ZR, 4)

def test_match_fails_when_receiver_does_not_satisfy_sender_policy(scheme_data):
    scheme, pk, msk = scheme_data

    sender_attributes = {1: 1, 2: 0, 3: 1}
    receiver_attributes = {1: 0, 2: 0, 3: 1}

    sender = scheme.sender_keygen(pk, msk, sender_attributes)
    receiver = scheme.receiver_keygen(pk, msk, receiver_attributes)

    sender_policy = scheme.policy_keygen(pk, msk, "a1v1")
    receiver_policy = scheme.policy_keygen(pk, msk, "a2v0")

    ciphertext = scheme.encrypt(pk, msk,
        sender,
        sender_policy,
        TEST_X,
    )
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

    ciphertext = scheme.encrypt(pk, msk,
        sender,
        sender_policy,
        TEST_X,
    )
    trapdoor, _ = scheme.transform_keygen(receiver, receiver_policy)

    assert scheme.match(
        ciphertext,
        trapdoor,
        sender_attributes,
        receiver_attributes,
    ) is None

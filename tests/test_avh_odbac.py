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

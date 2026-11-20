import inspect

import pytest

from charm.toolbox.pairinggroup import PairingGroup, ZR

from ABE.avh_odbac.avh_odbac_privacy_proto_v3 import (
    AVHODBACPrivacyPrototypeV3,
)


X = [1, 2, 3]
Y = [1, 0, 1]

SENDER = {1: 1, 2: 0, 3: 1}
RECEIVER = {1: 1, 2: 0, 3: 0}

POLICY = "(a1v1 and a2v0)"


@pytest.fixture
def data():

    scheme = AVHODBACPrivacyPrototypeV3(
        PairingGroup("SS512"),
        universe_size=3,
    )

    mpk, msk = scheme.setup()

    return scheme, mpk, msk


def make_flow(
    scheme,
    mpk,
    msk,
    sender,
    receiver,
    sender_session,
    receiver_session=None,
    policy_session=None,
    sender_policy=POLICY,
    receiver_policy=POLICY,
):

    if receiver_session is None:
        receiver_session = sender_session

    if policy_session is None:
        policy_session = sender_session

    sender_sk, sender_mu, sender_tokens = (
        scheme.sender_keygen_with_tokens(
            mpk, msk, sender, sender_session
        )
    )

    receiver_rk, receiver_theta, receiver_tokens = (
        scheme.receiver_keygen_with_tokens(
            mpk, msk, receiver, receiver_session
        )
    )

    pk_S, pk_R = scheme.policy_keygen(
        mpk,
        msk,
        sender_policy,
        receiver_policy,
        policy_session,
    )

    ciphertext = scheme.encrypt(
        mpk,
        sender_sk,
        sender_mu,
        pk_S,
        X,
        sender_tokens,
    )

    trapdoor, local_secret = scheme.transform_keygen(
        receiver_rk,
        receiver_theta,
        pk_R,
        receiver_tokens,
    )

    return ciphertext, trapdoor, local_secret


def test_match_accepts_only_ciphertext_and_trapdoor(data):

    scheme, _, _ = data

    parameters = list(
        inspect.signature(scheme.match).parameters
    )

    assert parameters == ["ciphertext", "trapdoor"]


def test_different_sessions_produce_different_tokens(data):

    scheme, _, msk = data

    session_A = scheme.new_session_id()
    session_B = scheme.new_session_id()

    tokens_A = scheme.issue_attribute_tokens(
        msk, SENDER, session_A
    )

    tokens_B = scheme.issue_attribute_tokens(
        msk, SENDER, session_B
    )

    assert tokens_A != tokens_B

    for index in SENDER:
        assert tokens_A[index] != tokens_B[index]


def test_same_session_produces_matching_tokens(data):

    scheme, _, msk = data

    session_id = scheme.new_session_id()

    sender_tokens = scheme.issue_attribute_tokens(
        msk, SENDER, session_id
    )

    receiver_tokens = scheme.issue_attribute_tokens(
        msk, RECEIVER, session_id
    )

    # Both parties have value 1 at attribute index 1.
    assert sender_tokens[1] == receiver_tokens[1]

    # Both parties have value 0 at attribute index 2.
    assert sender_tokens[2] == receiver_tokens[2]


def test_authorized_matching_and_functional_decryption(data):

    scheme, mpk, msk = data

    session_id = scheme.new_session_id()

    ciphertext, trapdoor, local_secret = make_flow(
        scheme,
        mpk,
        msk,
        SENDER,
        RECEIVER,
        session_id,
    )

    partial = scheme.match(ciphertext, trapdoor)

    assert partial is not None

    sk_y = scheme.fkgen(msk, Y)

    result = scheme.final_decrypt(
        ciphertext,
        partial,
        local_secret,
        sk_y,
        Y,
    )

    expected = (
        ciphertext["base_pairing"]
        ** scheme.group.init(ZR, 4)
    )

    assert result == expected


def test_cross_session_replay_is_rejected(data):

    scheme, mpk, msk = data

    session_A = scheme.new_session_id()
    session_B = scheme.new_session_id()

    ciphertext, trapdoor, _ = make_flow(
        scheme,
        mpk,
        msk,
        SENDER,
        RECEIVER,
        sender_session=session_A,
        receiver_session=session_B,
        policy_session=session_A,
    )

    # Receiver's attributes use session B tags.
    # Sender policy expects session A tags.
    assert scheme.match(ciphertext, trapdoor) is None


def test_reject_receiver_failing_sender_policy(data):

    scheme, mpk, msk = data

    session_id = scheme.new_session_id()

    sender = {1: 1, 2: 0, 3: 1}
    receiver = {1: 0, 2: 0, 3: 1}

    ciphertext, trapdoor, _ = make_flow(
        scheme,
        mpk,
        msk,
        sender,
        receiver,
        session_id,
        sender_policy="a1v1",
        receiver_policy="a2v0",
    )

    assert scheme.match(ciphertext, trapdoor) is None


def test_reject_sender_failing_receiver_policy(data):

    scheme, mpk, msk = data

    session_id = scheme.new_session_id()

    sender = {1: 0, 2: 0, 3: 1}
    receiver = {1: 1, 2: 0, 3: 1}

    ciphertext, trapdoor, _ = make_flow(
        scheme,
        mpk,
        msk,
        sender,
        receiver,
        session_id,
        sender_policy="a2v0",
        receiver_policy="a1v1",
    )

    assert scheme.match(ciphertext, trapdoor) is None


def test_csp_payload_has_no_plaintext_attribute_labels(data):

    scheme, mpk, msk = data

    session_id = scheme.new_session_id()

    ciphertext, trapdoor, _ = make_flow(
        scheme,
        mpk,
        msk,
        SENDER,
        RECEIVER,
        session_id,
    )

    payload = repr((ciphertext, trapdoor)).lower()

    assert "a1v1" not in payload
    assert "a2v0" not in payload

    assert "sender_row_attribute_indices" not in payload
    assert "receiver_row_attribute_indices" not in payload

    assert "sender_attributes" not in payload
    assert "receiver_attributes" not in payload

    assert scheme.TOKEN_KEY_NAME not in ciphertext
    assert scheme.TOKEN_KEY_NAME not in trapdoor


def test_modified_token_is_rejected(data):

    scheme, mpk, msk = data

    session_id = scheme.new_session_id()

    ciphertext, trapdoor, _ = make_flow(
        scheme,
        mpk,
        msk,
        SENDER,
        RECEIVER,
        session_id,
    )

    original_token = scheme._session_attribute_token(
        msk, session_id, 1, RECEIVER[1]
    )

    tokens = list(trapdoor["receiver_attribute_tokens"])

    assert original_token in tokens

    modified_token = "0" * 64

    if modified_token in tokens:
        modified_token = "f" * 64

    tokens[tokens.index(original_token)] = modified_token

    trapdoor["receiver_attribute_tokens"] = tokens

    tr1 = dict(trapdoor["tr1"])

    component = tr1.pop(original_token)
    tr1[modified_token] = component

    trapdoor["tr1"] = tr1

    assert scheme.match(ciphertext, trapdoor) is None


def test_kgc_can_reconstruct_session_token_mapping(data):

    scheme, _, msk = data

    session_A = scheme.new_session_id()
    session_B = scheme.new_session_id()

    # A legitimate participant knows its own token map.
    known_mapping_A = scheme.issue_attribute_tokens(
        msk, SENDER, session_A
    )

    # It can identify its own tokens in the current session.
    assert known_mapping_A[1] == (
        scheme._session_attribute_token(
            msk, session_A, 1, SENDER[1]
        )
    )

    # But this token does not directly identify the same
    # attribute-value in a different session.
    mapping_B = scheme.issue_attribute_tokens(
        msk, SENDER, session_B
    )

    assert known_mapping_A[1] != mapping_B[1]


def test_or_policy_authorized_matching(data):

    scheme, mpk, msk = data
    session_id = scheme.new_session_id()

    # Both parties satisfy a1v1.
    or_policy = "(a1v1 or a2v1)"

    ciphertext, trapdoor, local_secret = make_flow(
        scheme,
        mpk,
        msk,
        SENDER,
        RECEIVER,
        session_id,
        sender_policy=or_policy,
        receiver_policy=or_policy,
    )

    partial = scheme.match(ciphertext, trapdoor)

    assert partial is not None

    sk_y = scheme.fkgen(msk, Y)

    result = scheme.final_decrypt(
        ciphertext,
        partial,
        local_secret,
        sk_y,
        Y,
    )

    expected = (
        ciphertext["base_pairing"]
        ** scheme.group.init(ZR, 4)
    )

    assert result == expected


def test_complete_session_pair_can_be_replayed(data):

    scheme, mpk, msk = data
    session_id = scheme.new_session_id()

    ciphertext, trapdoor, _ = make_flow(
        scheme,
        mpk,
        msk,
        SENDER,
        RECEIVER,
        session_id,
    )

    first_result = scheme.match(ciphertext, trapdoor)
    replay_result = scheme.match(ciphertext, trapdoor)

    # Documents that Version 3 has no replay-expiry mechanism.
    assert first_result is not None
    assert replay_result is not None
    assert first_result["mh"] == replay_result["mh"]

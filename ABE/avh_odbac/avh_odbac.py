from charm.toolbox.pairinggroup import ZR, G1, G2, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AVHODBAC(ABEnc):

    def __init__(self, group_obj, universe_size, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.universe_size = universe_size
        self.util = MSP(self.group, verbose)

    def _random_nonzero(self):
        value = self.group.random(ZR)
        while value == 0:
            value = self.group.random(ZR)
        return value

    def _validate_attributes(self, attributes):
        expected = set(range(1, self.universe_size + 1))

        if set(attributes.keys()) != expected:
            raise ValueError(
                "attributes must contain every index from 1 to universe_size"
            )

        if any(value not in (0, 1) for value in attributes.values()):
            raise ValueError("every attribute value must be 0 or 1")

    def _parse_policy_literal(self, literal):
        base = literal.split("_")[0].lower()

        if not base.startswith("a") or "v" not in base:
            raise ValueError(
                "policy attributes must use the form a<index>v<0-or-1>"
            )

        index_text, value_text = base[1:].split("v", 1)
        index = int(index_text)
        value = int(value_text)

        if index not in range(1, self.universe_size + 1):
            raise ValueError("policy attribute index is outside the universe")

        if value not in (0, 1):
            raise ValueError("policy attribute value must be 0 or 1")

        return index, value

    def setup(self):
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)

        f = self._random_nonzero()
        t = {}
        e = {}

        for i in range(1, self.universe_size + 1):
            t[i] = self._random_nonzero()
            e[i] = self._random_nonzero()

        pk = {
            "g1": g1,
            "g2": g2,
            "F": g1 ** f,
            "T": {i: g1 ** t[i] for i in t},
            "E": {i: g1 ** e[i] for i in e},
            "universe_size": self.universe_size,
        }

        msk = {
            "f": f,
            "t": t,
            "e": e,
        }

        return pk, msk

    def sender_keygen(self, pk, msk, attributes):
        self._validate_attributes(attributes)
        mu = self._random_nonzero()
        components = {}

        for i, value in attributes.items():
            denominator = msk["t"][i] if value == 1 else msk["e"][i]
            components[i] = pk["g2"] ** (mu / denominator)

        return {
            "role": "sender",
            "user_id": mu,
            "attributes": dict(attributes),
            "K": components,
        }

    def receiver_keygen(self, pk, msk, attributes):
        self._validate_attributes(attributes)
        theta = self._random_nonzero()
        components = {}

        for i, value in attributes.items():
            denominator = msk["t"][i] if value == 1 else msk["e"][i]
            components[i] = pk["g2"] ** (theta / denominator)

        return {
            "role": "receiver",
            "user_id": theta,
            "attributes": dict(attributes),
            "K": components,
        }

    def policy_keygen(self, pk, msk, policy_str):
        policy = self.util.createPolicy(policy_str)
        msp = self.util.convert_policy_to_msp(policy)
        width = self.util.len_longest_row

        sharing_vector = [msk["f"]]
        for _ in range(1, width):
            sharing_vector.append(self.group.random(ZR))

        components = {}

        for literal, row in msp.items():
            lambda_value = self.group.init(ZR, 0)

            for column, coefficient in enumerate(row):
                lambda_value += coefficient * sharing_vector[column]

            index, value = self._parse_policy_literal(literal)
            factor = msk["t"][index] if value == 1 else msk["e"][index]
            components[literal] = pk["g1"] ** (lambda_value * factor)

        return {
            "policy_str": policy_str,
            "policy": policy,
            "msp": msp,
            "width": width,
            "components": components,
        }
    def _derive_symmetric_key(self, pairing_element):
        
        serialized = self.group.serialize(pairing_element)
        return hashlib.sha256(serialized).digest()

    def encrypt(self, pk, sender_key, sender_policy_key, plaintext):
        if sender_key["role"] != "sender":
            raise ValueError("encrypt requires a sender key")

        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        alpha = self._random_nonzero()
        beta = self._random_nonzero()

        session_element = (
            pair(pk["F"], pk["g2"] ** alpha)
            * pair(pk["F"], pk["g2"] ** beta)
        )

        aes_key = self._derive_symmetric_key(session_element)
        nonce = os.urandom(12)
        associated_data = b"AVH-OD-BAC-v1"
        encrypted_payload = AESGCM(aes_key).encrypt(
            nonce,
            plaintext,
            associated_data,
        )

        ct2 = {
            index: component ** beta
            for index, component in sender_key["K"].items()
        }

        ct3 = {
            literal: component ** alpha
            for literal, component in sender_policy_key["components"].items()
        }

        return {
            "sender_id": sender_key["user_id"],
            "sender_policy": sender_policy_key["policy"],
            "sender_msp": sender_policy_key["msp"],
            "ct2": ct2,
            "ct3": ct3,
            "nonce": nonce,
            "associated_data": associated_data,
            "payload": encrypted_payload,
        }

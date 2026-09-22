from charm.toolbox.pairinggroup import ZR, G1, G2
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP


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
        pass

    def encrypt(self, pk, sender_key, sender_policy_key, plaintext):
        pass

    def transform_keygen(self, receiver_key, receiver_policy_key):
        pass

    def match(self, pk, ciphertext, trapdoor, cloud_registry):
        pass

    def final_decrypt(self, partial_ciphertext, ciphertext, local_secret):
        pass

    def revoke(self, cloud_registry, user_id):
        pass

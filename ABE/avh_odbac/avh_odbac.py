from charm.toolbox.pairinggroup import ZR, G1, G2, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag




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
    def transform_keygen(self, receiver_key, receiver_policy_key):
        if receiver_key["role"] != "receiver":
            raise ValueError("transform_keygen requires a receiver key")

        x = self._random_nonzero()
        delta = self._random_nonzero()
        blind = x * delta

        tr1 = {
            index: component ** blind
            for index, component in receiver_key["K"].items()
        }

        tr2 = {
            literal: component ** blind
            for literal, component in receiver_policy_key["components"].items()
        }

        trapdoor = {
            "receiver_id": receiver_key["user_id"],
            "receiver_policy": receiver_policy_key["policy"],
            "receiver_msp": receiver_policy_key["msp"],
            "tr1": tr1,
            "tr2": tr2,
        }

        local_secret = {
            "x": x,
            "delta": delta,
        }

        return trapdoor, local_secret
    def _attribute_labels(self, attributes):
        self._validate_attributes(attributes)

        return [
            "a{}v{}".format(index, value).upper()
            for index, value in attributes.items()
        ]
    def _msp_reconstruction_coefficients(self, msp, nodes):
        literals = [node.getAttributeAndIndex() for node in nodes]
        width = max(len(msp[literal]) for literal in literals)
        variable_count = len(literals)

        zero = self.group.init(ZR, 0)
        one = self.group.init(ZR, 1)

        augmented = []

        for equation in range(width):
            row = []

            for literal in literals:
                msp_row = msp[literal]
                value = msp_row[equation] if equation < len(msp_row) else 0
                row.append(self.group.init(ZR, value))

            row.append(one if equation == 0 else zero)
            augmented.append(row)

        pivot_row = 0
        pivot_columns = []

        for column in range(variable_count):
            pivot = None

            for row in range(pivot_row, width):
                if augmented[row][column] != zero:
                    pivot = row
                    break

            if pivot is None:
                continue

            augmented[pivot_row], augmented[pivot] = (
                augmented[pivot],
                augmented[pivot_row],
            )

            inverse = one / augmented[pivot_row][column]
            augmented[pivot_row] = [
                value * inverse for value in augmented[pivot_row]
            ]

            for row in range(width):
                if row == pivot_row:
                    continue

                factor = augmented[row][column]

                if factor != zero:
                    augmented[row] = [
                        augmented[row][item] -
                        factor * augmented[pivot_row][item]
                        for item in range(variable_count + 1)
                    ]

            pivot_columns.append(column)
            pivot_row += 1

            if pivot_row == width:
                break

        for row in range(pivot_row, width):
            if all(
                augmented[row][column] == zero
                for column in range(variable_count)
            ) and augmented[row][-1] != zero:
                raise ValueError("selected MSP rows cannot reconstruct the secret")

        solution = [zero for _ in range(variable_count)]

        for row, column in enumerate(pivot_columns):
            solution[column] = augmented[row][-1]

        return {
            literal: solution[index]
            for index, literal in enumerate(literals)
        }


    def match(
        self,
        ciphertext,
        trapdoor,
        sender_attributes,
        receiver_attributes,
    ):
        """
        Research-prototype cloud match.

        sender_attributes and receiver_attributes are visible to the cloud in
        this version. Replace this interface before claiming attribute privacy.
        """
        sender_labels = self._attribute_labels(sender_attributes)
        receiver_labels = self._attribute_labels(receiver_attributes)

        sender_nodes = self.util.prune(
            ciphertext["sender_policy"],
            receiver_labels,
        )

        receiver_nodes = self.util.prune(
            trapdoor["receiver_policy"],
            sender_labels,
        )

        if not sender_nodes or not receiver_nodes:
            return None

        sender_coefficients = self._msp_reconstruction_coefficients(
            ciphertext["sender_msp"],
            sender_nodes,
        )

        receiver_coefficients = self._msp_reconstruction_coefficients(
            trapdoor["receiver_msp"],
            receiver_nodes,
        )

        mh = 1

        for node in sender_nodes:
            literal = node.getAttributeAndIndex()
            index, _ = self._parse_policy_literal(literal)

            ct3_adjusted = (
                ciphertext["ct3"][literal]
                ** (1 / trapdoor["receiver_id"])
            )

            mh *= (
                pair(ct3_adjusted, trapdoor["tr1"][index])
                ** sender_coefficients[literal]
            )

        for node in receiver_nodes:
            literal = node.getAttributeAndIndex()
            index, _ = self._parse_policy_literal(literal)

            ct2_adjusted = (
                ciphertext["ct2"][index]
                ** (1 / ciphertext["sender_id"])
            )

            mh *= (
                pair(trapdoor["tr2"][literal], ct2_adjusted)
                ** receiver_coefficients[literal]
            )

        return {"mh": mh}
    def final_decrypt(self, ciphertext, partial_ciphertext, local_secret):
        if partial_ciphertext is None:
            return None

        if "mh" not in partial_ciphertext:
            raise ValueError("partial ciphertext does not contain mh")

        blind = local_secret["x"] * local_secret["delta"]

        session_element = partial_ciphertext["mh"] ** (1 / blind)
        aes_key = self._derive_symmetric_key(session_element)

        try:
            return AESGCM(aes_key).decrypt(
                ciphertext["nonce"],
                ciphertext["payload"],
                ciphertext["associated_data"],
            )
        except InvalidTag:
            return None

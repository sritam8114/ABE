from charm.toolbox.pairinggroup import ZR, G1, G2, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag




class AVHODBAC(ABEnc):
    def _user_token(self, user_id):
        return self.group.serialize(user_id)

    def revoke(self, revoked_user_ids, user_id):
        revoked_user_ids.add(self._user_token(user_id))

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
        s = {}

        for i in range(1, self.universe_size + 1):
            t[i] = self._random_nonzero()
            e[i] = self._random_nonzero()
            s[i] = self._random_nonzero()

        pk = {
            "g1": g1,
            "g2": g2,
            "F": g1 ** f,
            "T": {i: g1 ** t[i] for i in t},
            "E": {i: g1 ** e[i] for i in e},
        "H": {i: g1 ** s[i] for i in s},
            "universe_size": self.universe_size,
        }

        msk = {
            "f": f,
            "t": t,
            "e": e,
        "s": s,
        }

        return pk, msk

    def sender_keygen(self, pk, msk, attributes):
        self._validate_attributes(attributes)
        mu = self._random_nonzero()
        components = {}
        sk_values = {}

        for i, value in attributes.items():
            denominator = msk["t"][i] if value == 1 else msk["e"][i]
            sk_i = mu / denominator
            components[i] = pk["g2"] ** sk_i
            sk_values[i] = sk_i

        return {
            "role": "sender",
            "user_id": mu,
            "attributes": dict(attributes),
            "K": components,
            "sk_values": sk_values,
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

    def fkgen(self, msk, y):
        if not isinstance(y, (list, tuple)):
            raise TypeError("y must be a list or tuple")

        if len(y) != self.universe_size:
            raise ValueError(
                "y length must equal universe_size"
            )

        sk_y = self.group.init(ZR, 0)

        for k in range(1, self.universe_size + 1):
            y_k = self.group.init(ZR, y[k - 1])
            sk_y += (msk["s"][k] / msk["f"]) * y_k

        return sk_y

    def encrypt(self, pk, sender_key, sender_policy_key, plaintext,data_vector):
        if sender_key["role"] != "sender":
            raise ValueError("encrypt requires a sender key")

        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not isinstance(data_vector, (list, tuple)):
            raise TypeError("data_vector must be a list or tuple")

        if len(data_vector) != self.universe_size:
            raise ValueError(
                  "data_vector length must equal universe_size"
            )

        alpha = self._random_nonzero()
        beta = self._random_nonzero()
        s = alpha + beta

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
        base_pairing = pair(pk["g1"], pk["g2"])
        g2_s = pk["g2"] ** s
        ck = {}

        for k in sender_key["attributes"]:
            if k not in pk["H"]:
                raise ValueError(
                    "missing H component for attribute {}".format(k)
                )

            x_k = self.group.init(ZR, data_vector[k - 1])
            h_k = pk["H"][k]

            ck[k] = (
                pair(h_k, g2_s)
                * (base_pairing ** x_k)
            )

        return {
            "sender_id": sender_key["user_id"],
            "sender_policy": sender_policy_key["policy"],
            "sender_msp": sender_policy_key["msp"],
            "ct2": ct2,
            "ct3": ct3,
            "ck": ck,
            "K": session_element,
            "data_vector": list(data_vector),
            "base_pairing": base_pairing,
            "nonce": nonce,
            "associated_data": associated_data,
            "payload": encrypted_payload,
        }
    def transform_keygen(self, receiver_key, receiver_policy_key):
        if receiver_key["role"] != "receiver":
            raise ValueError("transform_keygen requires a receiver key")

        tau = self._random_nonzero()
        delta = self._random_nonzero()
        blind = tau * delta

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
            "tau": tau,
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
    revoked_user_ids=None,

    ):

        if revoked_user_ids is not None:
            sender_token = self._user_token(ciphertext["sender_id"])
            receiver_token = self._user_token(trapdoor["receiver_id"])

            if (
                sender_token in revoked_user_ids
                or receiver_token in revoked_user_ids
            ):
                return None
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
    def final_decrypt(
        self,
        ciphertext,
        partial_ciphertext,
        local_secret,
        sk_y,
        y,
    ):
        if partial_ciphertext is None:
            return None

        if "mh" not in partial_ciphertext:
            raise ValueError("partial ciphertext does not contain mh")

        if not isinstance(y, (list, tuple)):
            raise TypeError("y must be a list or tuple")

        if len(y) != self.universe_size:
            raise ValueError(
                "y length must equal universe_size"
            )

        if "ck" not in ciphertext:
            raise ValueError("ciphertext does not contain ck")

        if "K" not in ciphertext:
            raise ValueError("ciphertext does not contain K")

        if "data_vector" not in ciphertext:
            raise ValueError("ciphertext does not contain data_vector")

        if "base_pairing" not in ciphertext:
            raise ValueError("ciphertext does not contain base_pairing")

        x = ciphertext["data_vector"]

        if len(x) != self.universe_size:
            raise ValueError(
                "data_vector length must equal universe_size"
            )

        # Recover the pairing/session element using the modified TrGen
        # variable tau instead of the original x.
        blind = local_secret["tau"] * local_secret["delta"]
        session_element = partial_ciphertext["mh"] ** (1 / blind)

        aes_key = self._derive_symmetric_key(session_element)

        try:
            recovered_plaintext = AESGCM(aes_key).decrypt(
                ciphertext["nonce"],
                ciphertext["payload"],
                ciphertext["associated_data"],
            )
        except InvalidTag:
            return None

        # ----------------------------------------------------------
        # Part 3: Functional-key verification
        #
        # D = product(C_k ^ y_k) / K ^ SK_y
        # Check:
        # D == e(g,g) ^ <x,y>
        # ----------------------------------------------------------

        ck_values = ciphertext["ck"]

        for k in range(1, self.universe_size + 1):
            if k not in ck_values:
                raise ValueError(
                    "ciphertext missing C_k for attribute {}".format(k)
                )

        # GT identity from an existing pairing element.
        first_ck = ck_values[1]
        numerator = first_ck ** 0

        for k in range(1, self.universe_size + 1):
            y_k = self.group.init(ZR, y[k - 1])
            numerator *= ck_values[k] ** y_k

        denominator = ciphertext["K"] ** sk_y
        D = numerator / denominator

        inner_product = self.group.init(ZR, 0)

        for k in range(1, self.universe_size + 1):
            x_k = self.group.init(ZR, x[k - 1])
            y_k = self.group.init(ZR, y[k - 1])
            inner_product += x_k * y_k

        expected_D = ciphertext["base_pairing"] ** inner_product

        if D != expected_D:
            return None

        return recovered_plaintext

    def _build_opaque_policy(self, policy_spec, prefix, state):
        if "index" in policy_spec and "value" in policy_spec:
            index = policy_spec["index"]
            value = policy_spec["value"]

            if index not in range(1, self.universe_size + 1):
                raise ValueError("policy attribute index is outside the universe")

            if value not in (0, 1):
                raise ValueError("policy attribute value must be 0 or 1")

            row_id = "{}{}".format(prefix, state["next_row"])
            state["next_row"] += 1
            state["row_values"][row_id] = (index, value)

            return row_id

        if "and" in policy_spec:
            left, right = policy_spec["and"]

            return "({} and {})".format(
                self._build_opaque_policy(left, prefix, state),
                self._build_opaque_policy(right, prefix, state),
            )

        if "or" in policy_spec:
            left, right = policy_spec["or"]

            return "({} or {})".format(
                self._build_opaque_policy(left, prefix, state),
                self._build_opaque_policy(right, prefix, state),
            )

        raise ValueError("invalid structured policy")

    def policy_keygen_hidden(self, pk, msk, policy_spec, prefix):
        state = {
            "next_row": 0,
            "row_values": {},
        }

        opaque_policy_str = self._build_opaque_policy(
            policy_spec,
            prefix,
            state,
        )

        opaque_policy = self.util.createPolicy(opaque_policy_str)
        opaque_msp = self.util.convert_policy_to_msp(opaque_policy)
        width = self.util.len_longest_row

        sharing_vector = [msk["f"]]
        for _ in range(1, width):
            sharing_vector.append(self.group.random(ZR))

        components = {}
        row_to_index = {}

        for literal, row in opaque_msp.items():
            opaque_row_id = literal.lower()
            index, value = state["row_values"][opaque_row_id]

            lambda_value = self.group.init(ZR, 0)

            for column, coefficient in enumerate(row):
                lambda_value += coefficient * sharing_vector[column]

            factor = msk["t"][index] if value == 1 else msk["e"][index]

            components[literal] = pk["g1"] ** (lambda_value * factor)
            row_to_index[literal] = index

        return {
            "components": components,
            "cloud_policy": {
                "opaque_policy": opaque_policy,
                "opaque_msp": opaque_msp,
                "row_to_index": row_to_index,
            },
        }

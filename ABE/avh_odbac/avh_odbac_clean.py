from charm.toolbox.pairinggroup import ZR, G1, G2, pair
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

        for i, value in attributes.items():
            denominator = msk["t"][i] if value == 1 else msk["e"][i]
            sk_i = mu / denominator
            components[i] = pk["g2"] ** sk_i

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
    def fkgen(self, msk, y):
        """
        Part 3: FKGen(msk, y) -> SK_y

        y = (y_1, ..., y_n), y_k in {0,1}

        SK_y = sum_k ((s_k / f) * y_k) mod p

        Charm's ZR arithmetic performs the modulo-p operation.
        """
        if not isinstance(y, (list, tuple)):
            raise TypeError("y must be a list or tuple")

        if len(y) != self.universe_size:
            raise ValueError("y length must equal universe_size")

        sk_y = self.group.init(ZR, 0)

        for k in range(1, self.universe_size + 1):
            y_k = self.group.init(ZR, y[k - 1])
            sk_y += (msk["s"][k] / msk["f"]) * y_k

        return sk_y

    def encrypt(self, pk, msk, sender_key, sender_policy_key, x):
        if sender_key["role"] != "sender":
            raise ValueError("encrypt requires a sender key")

        if not isinstance(x, (list, tuple)):
            raise TypeError("x must be a list or tuple")

        if len(x) != self.universe_size:
            raise ValueError(
                "x length must equal universe_size"
            )

        alpha = self._random_nonzero()
        beta = self._random_nonzero()
        s = alpha + beta

        # K = e(F, g^s), where s = alpha + beta.
        K = pair(pk["F"], pk["g2"] ** s)

        ct2 = {
            index: component ** beta
            for index, component in sender_key["K"].items()
        }

        ct3 = {
            literal: component ** alpha
            for literal, component in sender_policy_key["components"].items()
        }

        base_pairing = pair(pk["g1"], pk["g2"])
        ck = {}

        for k in range(1, self.universe_size + 1):
            s_k = msk["s"][k]
            x_k = self.group.init(ZR, x[k - 1])

            # Exact requested formula:
            # C_k = e(g,g)^(s*s_k) * e(g,g)^x_k
            ck[k] = (
                (base_pairing ** (s * s_k))
                * (base_pairing ** x_k)
            )

        return {
            "sender_id": sender_key["user_id"],
            "sender_policy": sender_policy_key["policy"],
            "sender_msp": sender_policy_key["msp"],
            "ct2": ct2,
            "ct3": ct3,
            "ck": ck,
            "K": K,
            "base_pairing": base_pairing,
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
    def compute_D(self, ciphertext, sk_y, x, y):
        """
        Part 3 verification.

        D = product(C_k ^ y_k) / K ^ SK_y

        Check:
            D == e(g,g) ^ <x,y>
        """
        if not isinstance(x, (list, tuple)):
            raise TypeError("x must be a list or tuple")

        if not isinstance(y, (list, tuple)):
            raise TypeError("y must be a list or tuple")

        if len(x) != self.universe_size:
            raise ValueError("x length must equal universe_size")

        if len(y) != self.universe_size:
            raise ValueError("y length must equal universe_size")

        if "ck" not in ciphertext:
            raise ValueError("ciphertext does not contain ck")

        if "K" not in ciphertext:
            raise ValueError("ciphertext does not contain K")

        if "base_pairing" not in ciphertext:
            raise ValueError("ciphertext does not contain base_pairing")

        # Every C_k must exist.
        for k in range(1, self.universe_size + 1):
            if k not in ciphertext["ck"]:
                raise ValueError(
                    "ciphertext missing C_k for attribute {}".format(k)
                )

        # ----------------------------------------------------
        # D = product(C_k ^ y_k) / K ^ SK_y
        # ----------------------------------------------------
        ck_values = ciphertext["ck"]

        # Identity element of G_T.
        numerator = ck_values[1] ** 0

        for k in range(1, self.universe_size + 1):
            y_k = self.group.init(ZR, y[k - 1])
            numerator *= ck_values[k] ** y_k

        denominator = ciphertext["K"] ** sk_y
        D = numerator / denominator

        # ----------------------------------------------------
        # Compute <x,y>
        # ----------------------------------------------------
        inner_product = self.group.init(ZR, 0)

        for k in range(1, self.universe_size + 1):
            x_k = self.group.init(ZR, x[k - 1])
            y_k = self.group.init(ZR, y[k - 1])
            inner_product += x_k * y_k

        # Expected value:
        # e(g,g) ^ <x,y>
        expected_D = ciphertext["base_pairing"] ** inner_product

        return {
            "D": D,
            "expected_D": expected_D,
            "inner_product": inner_product,
            "verified": D == expected_D,
        }


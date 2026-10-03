from charm.toolbox.pairinggroup import ZR, G1, G2, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP




class AVHODBAC(ABEnc):
    def __init__(self, group_obj, universe_size, verbose=False, B=10):
        ABEnc.__init__(self)
        self.group = group_obj
        self.universe_size = universe_size

        if not isinstance(B, int) or B < 0:
            raise ValueError("B must be a non-negative integer")

        self.B = B
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
        self._master_f = f
        t = {}
        e = {}
        s = {}

        for i in range(1, self.universe_size + 1):
            t[i] = self._random_nonzero()
            e[i] = self._random_nonzero()
            s[i] = self._random_nonzero()

        mpk = {
            "g1": g1,
            "g2": g2,
            "F": g1 ** f,
            "T": {i: g1 ** t[i] for i in t},
            "E": {i: g1 ** e[i] for i in e},
        "hk": {i: g1 ** s[i] for i in s},
            "universe_size": self.universe_size,
        }

        msk = {
            "f": f,
            "t": t,
            "e": e,
        "s": s,
        }

        return mpk, msk

    def sender_keygen(self, mpk, msk, attributes):
        self._validate_attributes(attributes)

        # Unique sender identifier mu, kept separate from sk.
        mu = self._random_nonzero()

        # sk = {sk_i}
        sk = {}

        for i, value in attributes.items():
            if value == 1:
                sk_i = mu / msk["t"][i]
            else:
                sk_i = mu / msk["e"][i]

            sk[i] = mpk["g2"] ** sk_i

        # Return the attribute secret key and mu separately.
        return sk, mu

    def receiver_keygen(self, mpk, msk, attributes):
        self._validate_attributes(attributes)

        theta = self._random_nonzero()
        rk = {}

        for i, value in attributes.items():
            if value == 1:
                rk_i = theta / msk["t"][i]
            else:
                rk_i = theta / msk["e"][i]

            rk[i] = mpk["g2"] ** rk_i

        return rk, theta

    def policy_keygen(self, mpk, msk, sender_policy_str, receiver_policy_str):
        """
        PolKeyGen(msk, S, R) -> (pk_S, pk_R)

        Sender:
            S = (M1, rho1)
            v_S = (f, xi_S,2, ..., xi_S,n1)^T
            lambda_S,j = M1,j . v_S

            If v = 1:
                pk_S,j = g^(lambda_S,j * t_i)

            If v = 0:
                pk_S,j = g^(lambda_S,j * e_i)

        Receiver:
            R = (M2, rho2)
            v_R = (f, xi_R,2, ..., xi_R,n2)^T
            lambda_R,j = M2,j . v_R

            If v = 1:
                pk_R,j = g^(lambda_R,j * t_i)

            If v = 0:
                pk_R,j = g^(lambda_R,j * e_i)
        """

        # ==========================================================
        # Sender policy: S = (M1, rho1)
        # ==========================================================

        sender_policy = self.util.createPolicy(sender_policy_str)
        sender_msp = self.util.convert_policy_to_msp(sender_policy)
        sender_width = self.util.len_longest_row

        # v_S = (f, xi_S,2, ..., xi_S,n1)^T
        sender_vector = [msk["f"]]

        for _ in range(1, sender_width):
            sender_vector.append(self.group.random(ZR))

        sender_components = {}

        # lambda_S,j = M1,j . v_S
        for literal, row in sender_msp.items():
            lambda_sender = self.group.init(ZR, 0)

            for column, coefficient in enumerate(row):
                lambda_sender += coefficient * sender_vector[column]

            # rho1(j) = (i, v)
            index, value = self._parse_policy_literal(literal)

            # v = 1 -> t_i
            # v = 0 -> e_i
            if value == 1:
                factor = msk["t"][index]
            else:
                factor = msk["e"][index]

            # pk_S,j = g^(lambda_S,j * t_i/e_i)
            sender_components[literal] = (
                mpk["g1"] ** (lambda_sender * factor)
            )

        pk_S = {
            "policy_str": sender_policy_str,
            "policy": sender_policy,
            "msp": sender_msp,
            "width": sender_width,
            "components": sender_components,
        }

        # ==========================================================
        # Receiver policy: R = (M2, rho2)
        # ==========================================================

        receiver_policy = self.util.createPolicy(receiver_policy_str)
        receiver_msp = self.util.convert_policy_to_msp(receiver_policy)
        receiver_width = self.util.len_longest_row

        # v_R = (f, xi_R,2, ..., xi_R,n2)^T
        receiver_vector = [msk["f"]]

        for _ in range(1, receiver_width):
            receiver_vector.append(self.group.random(ZR))

        receiver_components = {}

        # lambda_R,j = M2,j . v_R
        for literal, row in receiver_msp.items():
            lambda_receiver = self.group.init(ZR, 0)

            for column, coefficient in enumerate(row):
                lambda_receiver += coefficient * receiver_vector[column]

            # rho2(j) = (i, v)
            index, value = self._parse_policy_literal(literal)

            # v = 1 -> t_i
            # v = 0 -> e_i
            if value == 1:
                factor = msk["t"][index]
            else:
                factor = msk["e"][index]

            # pk_R,j = g^(lambda_R,j * t_i/e_i)
            receiver_components[literal] = (
                mpk["g1"] ** (lambda_receiver * factor)
            )

        pk_R = {
            "policy_str": receiver_policy_str,
            "policy": receiver_policy,
            "msp": receiver_msp,
            "width": receiver_width,
            "components": receiver_components,
        }

        # Paper output:
        # PolKeyGen(msk, S, R) -> (pk_S, pk_R)
        return pk_S, pk_R

    def fkgen(self, msk, y):
        """
        FKGen(msk, y) -> SK_y

        y = (y_1, y_2, ..., y_n) in [0, B]^n

        SK_y = sum_{k=1}^n (s_k / f) * y_k mod p
        """

        if not isinstance(y, (list, tuple)):
            raise TypeError("y must be a list or tuple")

        if len(y) != self.universe_size:
            raise ValueError(
                "y length must equal universe_size"
            )

        # Paper domain:
        # y = (y_1, ..., y_n) belongs to [0, B]^n
        for y_k in y:
            if not isinstance(y_k, int):
                raise TypeError("each y_k must be an integer")

            if y_k < 0 or y_k > self.B:
                raise ValueError(
                    "each y_k must satisfy 0 <= y_k <= B"
                )

        # SK_y = sum_{k=1}^n (s_k/f) * y_k mod p
        sk_y = self.group.init(ZR, 0)

        for k in range(1, self.universe_size + 1):
            y_k = self.group.init(ZR, y[k - 1])
            sk_y += (msk["s"][k] / msk["f"]) * y_k

        return sk_y

    def encrypt(self, mpk, sender_sk, sender_mu, pk_S, x):
        if not isinstance(x, (list, tuple)):
            raise TypeError("x must be a list or tuple")

        if len(x) != self.universe_size:
            raise ValueError(
                "x length must equal universe_size"
            )

        alpha = self._random_nonzero()
        beta = self._random_nonzero()
        s = alpha + beta

        ct2 = {
            index: component ** beta
            for index, component in sender_sk.items()
        }

        ct3 = {
            literal: component ** alpha
            for literal, component
            in pk_S["components"].items()
        }

        base_pairing = pair(mpk["g1"], mpk["g2"])
        g2_s = mpk["g2"] ** s
        ck = {}

        for k in range(1, self.universe_size + 1):
            x_k = self.group.init(ZR, x[k - 1])
            h_k = mpk["hk"][k]

            # C_k = e(g,g)^(s*s_k) * e(g,g)^(x_k)
            ck[k] = (
                pair(h_k, g2_s)
                * (base_pairing ** x_k)
            )

        ciphertext = {
            "sender_id": sender_mu,
            "sender_policy": pk_S["policy"],
            "sender_msp": pk_S["msp"],
            "ct2": ct2,
            "ct3": ct3,
            "ck": ck,
            "base_pairing": base_pairing,
            "s": s,
        }

        return ciphertext, s

    def transform_keygen(self, rk, theta, pk_R):
        """
        TrGen(rk, pk_R) -> TR

        The receiver randomly chooses:
            v <- Zp
            delta_u <- Zp

        and uses the corrected blinding exponent:
            v * delta_u

        TR1,u = rk_u^(v * delta_u)
        TR2,j = pk_R,j^(v * delta_u)

        theta is kept separately as the receiver identifier used
        by the CSP during the matching phase.
        """

        v = self._random_nonzero()
        delta_u = self._random_nonzero()
        blind = v * delta_u

        tr1 = {
            index: component ** blind
            for index, component in rk.items()
        }

        tr2 = {
            literal: component ** blind
            for literal, component
            in pk_R["components"].items()
        }

        trapdoor = {
            "receiver_id": theta,
            "receiver_policy": pk_R["policy"],
            "receiver_msp": pk_R["msp"],
            "tr1": tr1,
            "tr2": tr2,
        }

        local_secret = {
            "v": v,
            "delta": delta_u,
        }

        return trapdoor, local_secret

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
        self._validate_attributes(sender_attributes)
        self._validate_attributes(receiver_attributes)

        sender_labels = [
            "A{}V{}".format(index, value)
            for index, value in sender_attributes.items()
        ]

        receiver_labels = [
            "A{}V{}".format(index, value)
            for index, value in receiver_attributes.items()
        ]

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

        reconstruction_coefficients = {}

        for name, msp, nodes in (
            ("sender", ciphertext["sender_msp"], sender_nodes),
            ("receiver", trapdoor["receiver_msp"], receiver_nodes),
        ):
            literals = [
                node.getAttributeAndIndex()
                for node in nodes
            ]

            width = max(
                len(msp[literal])
                for literal in literals
            )

            variable_count = len(literals)

            zero = self.group.init(ZR, 0)
            one = self.group.init(ZR, 1)

            augmented = []

            for equation in range(width):
                row = []

                for literal in literals:
                    msp_row = msp[literal]

                    value = (
                        msp_row[equation]
                        if equation < len(msp_row)
                        else 0
                    )

                    row.append(
                        self.group.init(ZR, value)
                    )

                row.append(
                    one if equation == 0 else zero
                )

                augmented.append(row)

            pivot_row = 0
            pivot_columns = []

            for column in range(variable_count):
                pivot = None

                for row in range(
                    pivot_row,
                    width,
                ):
                    if augmented[row][column] != zero:
                        pivot = row
                        break

                if pivot is None:
                    continue

                augmented[pivot_row], augmented[pivot] = (
                    augmented[pivot],
                    augmented[pivot_row],
                )

                inverse = (
                    one
                    / augmented[pivot_row][column]
                )

                augmented[pivot_row] = [
                    value * inverse
                    for value in augmented[pivot_row]
                ]

                for row in range(width):
                    if row == pivot_row:
                        continue

                    factor = augmented[row][column]

                    if factor != zero:
                        augmented[row] = [
                            augmented[row][item]
                            - factor * augmented[pivot_row][item]
                            for item in range(
                                variable_count + 1
                            )
                        ]

                pivot_columns.append(column)
                pivot_row += 1

                if pivot_row == width:
                    break

            for row in range(
                pivot_row,
                width,
            ):
                if all(
                    augmented[row][column] == zero
                    for column in range(variable_count)
                ) and augmented[row][-1] != zero:
                    raise ValueError(
                        "selected MSP rows cannot reconstruct the secret"
                    )

            solution = [
                zero
                for _ in range(variable_count)
            ]

            for row, column in enumerate(
                pivot_columns
            ):
                solution[column] = augmented[row][-1]

            reconstruction_coefficients[name] = {
                literal: solution[index]
                for index, literal in enumerate(literals)
            }

        sender_coefficients = (
            reconstruction_coefficients["sender"]
        )

        receiver_coefficients = (
            reconstruction_coefficients["receiver"]
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
        x,
        y,
        s,
    ):
        """
        Final receiver-side verification.

        Teacher correction:

            MH = e(g,g)^(f*s*v*delta_u)

            K = MH^(1/(v*delta_u))

            D = product(C_k^y_k) / K^SK_y

            D = e(g,g)^<x,y>
        """

        if partial_ciphertext is None:
            return None

        if "mh" not in partial_ciphertext:
            raise ValueError("partial ciphertext does not contain mh")

        if "ck" not in ciphertext:
            raise ValueError("ciphertext does not contain ck")

        if "base_pairing" not in ciphertext:
            raise ValueError("ciphertext does not contain base_pairing")

        if s is None:
            raise ValueError("s is required for final verification")

        if not isinstance(x, (list, tuple)):
            raise TypeError("x must be a list or tuple")

        if not isinstance(y, (list, tuple)):
            raise TypeError("y must be a list or tuple")

        if len(x) != self.universe_size:
            raise ValueError(
                "x length must equal universe_size"
            )

        if len(y) != self.universe_size:
            raise ValueError(
                "y length must equal universe_size"
            )

        # ----------------------------------------------------------
        # 1. Recalculate MH exactly from the teacher's formula
        # ----------------------------------------------------------

        f = self._master_f
        # s is supplied separately by Encryption.
        v = local_secret["v"]
        delta_u = local_secret["delta"]

        calculated_mh = ciphertext["base_pairing"] ** (
            f * s * v * delta_u
        )

        if calculated_mh != partial_ciphertext["mh"]:
            print("    MH formula check      : FAILED")
            return None

        print("    MH formula check      : SUCCESS")

        # ----------------------------------------------------------
        # 2. Recover K from MH
        # ----------------------------------------------------------

        K = calculated_mh ** (
            1 / (v * delta_u)
        )

        print("    K reconstruction      : SUCCESS")

        # ----------------------------------------------------------
        # 3. Compute numerator = product(C_k ^ y_k)
        # ----------------------------------------------------------

        numerator = ciphertext["base_pairing"] ** self.group.init(
            ZR, 0
        )

        for k in range(1, self.universe_size + 1):
            if k not in ciphertext["ck"]:
                raise ValueError(
                    "ciphertext missing C_k for attribute {}".format(k)
                )

            y_k = self.group.init(ZR, y[k - 1])
            numerator *= ciphertext["ck"][k] ** y_k

        # ----------------------------------------------------------
        # 4. Compute denominator = K ^ SK_y
        # ----------------------------------------------------------

        denominator = K ** sk_y

        # ----------------------------------------------------------
        # 5. Compute D
        # ----------------------------------------------------------

        D = numerator / denominator

        # ----------------------------------------------------------
        # 6. Compute <x,y>
        # ----------------------------------------------------------

        inner_product = self.group.init(ZR, 0)

        for k in range(1, self.universe_size + 1):
            x_k = self.group.init(ZR, x[k - 1])
            y_k = self.group.init(ZR, y[k - 1])

            inner_product += x_k * y_k

        # ----------------------------------------------------------
        # 7. Expected D
        # ----------------------------------------------------------

        expected_D = ciphertext["base_pairing"] ** inner_product

        if D != expected_D:
            print("    D verification        : FAILED")
            print("    <x,y>                 :", inner_product)
            return None

        print("    D verification        : SUCCESS")
        print("    <x,y>                 :", inner_product)

        return inner_product


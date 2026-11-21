"""
Experimental AVH-ODBAC privacy-oriented matching extension.

Does not modify the verified avh_odbac.py implementation.

Uses KGC-generated HMAC-SHA256 tags instead of plaintext
attribute-value labels in the CSP-facing ciphertext and trapdoor.

This is an experimental extension, not a formally proven scheme.
"""

import hashlib
import hmac
import secrets

from charm.toolbox.pairinggroup import ZR, pair

from .avh_odbac import AVHODBAC


class AVHODBACPrivacyPrototype(AVHODBAC):

    TOKEN_KEY_NAME = "_attribute_token_key"
    TOKEN_DOMAIN = b"AVH-ODBAC-attribute-value-v1|"

    # ---------------------------------------------------------
    # SETUP
    # ---------------------------------------------------------

    def setup(self):
        mpk, msk = super().setup()

        # Secret held only by the trusted KGC.
        # Never send this key to the CSP.
        msk[self.TOKEN_KEY_NAME] = secrets.token_bytes(32)

        return mpk, msk

    # ---------------------------------------------------------
    # OPAQUE ATTRIBUTE TOKENS
    # ---------------------------------------------------------

    def _attribute_token(self, msk, index, value):

        if index not in range(1, self.universe_size + 1):
            raise ValueError("Invalid attribute index")

        if value not in (0, 1):
            raise ValueError("Attribute value must be 0 or 1")

        key = msk.get(self.TOKEN_KEY_NAME)

        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("Invalid KGC token key")

        message = (
            self.TOKEN_DOMAIN
            + f"{index}:{value}".encode("ascii")
        )

        return hmac.new(
            key,
            message,
            hashlib.sha256
        ).hexdigest()

    def issue_attribute_tokens(self, msk, attributes):

        self._validate_attributes(attributes)

        return {
            index: self._attribute_token(msk, index, value)
            for index, value in attributes.items()
        }

    def _validate_token_map(self, tokens, name):

        expected = set(range(1, self.universe_size + 1))

        if not isinstance(tokens, dict):
            raise ValueError(name + " must be a dictionary")

        if set(tokens.keys()) != expected:
            raise ValueError(
                name + " must contain all attribute indices"
            )

        for token in tokens.values():
            if not isinstance(token, str) or len(token) != 64:
                raise ValueError(name + " contains an invalid token")

    # ---------------------------------------------------------
    # KEY GENERATION WITH TOKENS
    # ---------------------------------------------------------

    def sender_keygen_with_tokens(self, mpk, msk, attributes):

        sender_sk, sender_mu = super().sender_keygen(
            mpk, msk, attributes
        )

        sender_tokens = self.issue_attribute_tokens(
            msk, attributes
        )

        return sender_sk, sender_mu, sender_tokens

    def receiver_keygen_with_tokens(self, mpk, msk, attributes):

        receiver_rk, receiver_theta = super().receiver_keygen(
            mpk, msk, attributes
        )

        receiver_tokens = self.issue_attribute_tokens(
            msk, attributes
        )

        return receiver_rk, receiver_theta, receiver_tokens

    # ---------------------------------------------------------
    # POLICY KEY GENERATION
    # ---------------------------------------------------------

    def _policy_key(self, mpk, msk, policy_str):

        policy = self.util.createPolicy(policy_str)

        raw_msp = self.util.convert_policy_to_msp(policy)

        width = self.util.len_longest_row

        sharing_vector = [msk["f"]]

        for _ in range(1, width):
            sharing_vector.append(self.group.random(ZR))

        msp_by_row = {}
        row_tokens = {}
        row_attribute_indices = {}
        components = {}

        for row_id, (literal, row) in enumerate(
            raw_msp.items(), start=1
        ):

            lambda_value = self.group.init(ZR, 0)

            for column, coefficient in enumerate(row):
                lambda_value += (
                    coefficient * sharing_vector[column]
                )

            index, value = self._parse_policy_literal(literal)

            factor = (
                msk["t"][index]
                if value == 1
                else msk["e"][index]
            )

            # Preserve the existing policy-key equation.
            components[row_id] = (
                mpk["g"] ** (lambda_value * factor)
            )

            # CSP sees integer row IDs, not a1v1/a2v0 labels.
            msp_by_row[row_id] = list(row)

            row_tokens[row_id] = self._attribute_token(
                msk, index, value
            )

            row_attribute_indices[row_id] = index

        return {
            "msp": msp_by_row,
            "width": width,
            "components": components,
            "row_tokens": row_tokens,
            "row_attribute_indices": row_attribute_indices,
        }

    def policy_keygen(
        self, mpk, msk, sender_policy_str, receiver_policy_str
    ):

        pk_S = self._policy_key(
            mpk, msk, sender_policy_str
        )

        pk_R = self._policy_key(
            mpk, msk, receiver_policy_str
        )

        return pk_S, pk_R

    # ---------------------------------------------------------
    # ENCRYPTION
    # ---------------------------------------------------------

    def encrypt(
        self,
        mpk,
        sender_sk,
        sender_mu,
        pk_S,
        x,
        sender_attribute_tokens,
    ):

        self._validate_token_map(
            sender_attribute_tokens,
            "sender_attribute_tokens",
        )

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
            row_id: component ** alpha
            for row_id, component in pk_S["components"].items()
        }

        base_pairing = pair(mpk["g"], mpk["g"])

        g_s = mpk["g"] ** s

        ck = {}

        for k in range(1, self.universe_size + 1):

            x_k = self.group.init(ZR, x[k - 1])

            h_k = mpk["hk"][k]

            # Teacher's functional-vector ciphertext equation.
            ck[k] = (
                pair(h_k, g_s)
                * (base_pairing ** x_k)
            )

        # Do not include plaintext policy tree or raw attributes.
        return {
            "sender_id": sender_mu,

            "sender_msp": pk_S["msp"],

            "sender_row_tokens": pk_S["row_tokens"],

            "sender_row_attribute_indices":
                pk_S["row_attribute_indices"],

            "sender_attribute_tokens":
                dict(sender_attribute_tokens),

            "ct2": ct2,
            "ct3": ct3,
            "ck": ck,
            "base_pairing": base_pairing,
        }

    # ---------------------------------------------------------
    # TRANSFORM KEY GENERATION
    # ---------------------------------------------------------

    def transform_keygen(
        self,
        receiver_rk,
        receiver_theta,
        pk_R,
        receiver_attribute_tokens,
    ):

        self._validate_token_map(
            receiver_attribute_tokens,
            "receiver_attribute_tokens",
        )

        v = self._random_nonzero()
        delta_u = self._random_nonzero()

        blind = v * delta_u

        tr1 = {
            index: component ** blind
            for index, component in receiver_rk.items()
        }

        tr2 = {
            row_id: component ** blind
            for row_id, component in pk_R["components"].items()
        }

        trapdoor = {
            "receiver_id": receiver_theta,

            "receiver_msp": pk_R["msp"],

            "receiver_row_tokens": pk_R["row_tokens"],

            "receiver_row_attribute_indices":
                pk_R["row_attribute_indices"],

            "receiver_attribute_tokens":
                dict(receiver_attribute_tokens),

            "tr1": tr1,
            "tr2": tr2,
        }

        # These values stay with the receiver.
        local_secret = {
            "v": v,
            "delta": delta_u,
        }

        return trapdoor, local_secret

    # ---------------------------------------------------------
    # ROW SELECTION USING OPAQUE TOKENS
    # ---------------------------------------------------------

    def _selected_rows(
        self,
        policy_row_tokens,
        row_attribute_indices,
        attribute_tokens,
    ):

        selected = []

        for row_id, row_token in policy_row_tokens.items():

            if row_id not in row_attribute_indices:
                raise ValueError("Missing row attribute index")

            index = row_attribute_indices[row_id]

            if attribute_tokens.get(index) == row_token:
                selected.append(row_id)

        return selected

    # ---------------------------------------------------------
    # MSP RECONSTRUCTION
    # ---------------------------------------------------------

    def _reconstruction_coefficients(self, msp, selected_rows):

        selected_rows = list(selected_rows)

        if not selected_rows:
            return None

        for row_id in selected_rows:
            if row_id not in msp:
                raise ValueError("Selected MSP row is missing")

        width = max(
            len(msp[row_id]) for row_id in selected_rows
        )

        variable_count = len(selected_rows)

        zero = self.group.init(ZR, 0)
        one = self.group.init(ZR, 1)

        # Solve:
        # sum_i omega_i * M_i = (1, 0, ..., 0)

        augmented = []

        for equation in range(width):

            row = []

            for row_id in selected_rows:

                source_row = msp[row_id]

                coefficient = (
                    source_row[equation]
                    if equation < len(source_row)
                    else 0
                )

                row.append(
                    self.group.init(ZR, coefficient)
                )

            row.append(
                one if equation == 0 else zero
            )

            augmented.append(row)

        pivot_row = 0
        pivot_columns = []

        for column in range(variable_count):

            if pivot_row >= width:
                break

            pivot = None

            for candidate in range(pivot_row, width):
                if augmented[candidate][column] != zero:
                    pivot = candidate
                    break

            if pivot is None:
                continue

            augmented[pivot_row], augmented[pivot] = (
                augmented[pivot],
                augmented[pivot_row],
            )

            inverse = one / augmented[pivot_row][column]

            augmented[pivot_row] = [
                value * inverse
                for value in augmented[pivot_row]
            ]

            for row_index in range(width):

                if row_index == pivot_row:
                    continue

                factor = augmented[row_index][column]

                if factor != zero:

                    augmented[row_index] = [
                        augmented[row_index][item]
                        - factor * augmented[pivot_row][item]
                        for item in range(variable_count + 1)
                    ]

            pivot_columns.append(column)
            pivot_row += 1

        # Reject inconsistent systems.
        for row_index in range(pivot_row, width):

            all_zero = all(
                augmented[row_index][column] == zero
                for column in range(variable_count)
            )

            if all_zero and augmented[row_index][-1] != zero:
                return None

        solution = [
            zero for _ in range(variable_count)
        ]

        for row_index, column in enumerate(pivot_columns):
            solution[column] = augmented[row_index][-1]

        # Verify the reconstructed target vector.
        for equation in range(width):

            total = zero

            for variable_index, row_id in enumerate(selected_rows):

                source_row = msp[row_id]

                coefficient = (
                    source_row[equation]
                    if equation < len(source_row)
                    else 0
                )

                total += (
                    solution[variable_index]
                    * self.group.init(ZR, coefficient)
                )

            expected = one if equation == 0 else zero

            if total != expected:
                return None

        return {
            row_id: solution[index]
            for index, row_id in enumerate(selected_rows)
        }

    # ---------------------------------------------------------
    # CSP MATCH: ONLY CT AND TR
    # ---------------------------------------------------------

    def match(self, ciphertext, trapdoor):

        required_ct = {
            "sender_id",
            "sender_msp",
            "sender_row_tokens",
            "sender_row_attribute_indices",
            "sender_attribute_tokens",
            "ct2",
            "ct3",
            "ck",
            "base_pairing",
        }

        required_tr = {
            "receiver_id",
            "receiver_msp",
            "receiver_row_tokens",
            "receiver_row_attribute_indices",
            "receiver_attribute_tokens",
            "tr1",
            "tr2",
        }

        if not required_ct.issubset(ciphertext):
            raise ValueError("Ciphertext metadata is incomplete")

        if not required_tr.issubset(trapdoor):
            raise ValueError("Trapdoor metadata is incomplete")

        self._validate_token_map(
            ciphertext["sender_attribute_tokens"],
            "sender_attribute_tokens",
        )

        self._validate_token_map(
            trapdoor["receiver_attribute_tokens"],
            "receiver_attribute_tokens",
        )

        # I1: Receiver satisfies sender's policy.
        sender_rows = self._selected_rows(
            ciphertext["sender_row_tokens"],
            ciphertext["sender_row_attribute_indices"],
            trapdoor["receiver_attribute_tokens"],
        )

        sender_coefficients = self._reconstruction_coefficients(
            ciphertext["sender_msp"],
            sender_rows,
        )

        if sender_coefficients is None:
            return None

        # I2: Sender satisfies receiver's policy.
        receiver_rows = self._selected_rows(
            trapdoor["receiver_row_tokens"],
            trapdoor["receiver_row_attribute_indices"],
            ciphertext["sender_attribute_tokens"],
        )

        receiver_coefficients = self._reconstruction_coefficients(
            trapdoor["receiver_msp"],
            receiver_rows,
        )

        if receiver_coefficients is None:
            return None

        mh = (
            ciphertext["base_pairing"]
            ** self.group.init(ZR, 0)
        )

        # Sender policy contribution.
        for row_id in sender_rows:

            index = (
                ciphertext["sender_row_attribute_indices"][row_id]
            )

            ct3_adjusted = (
                ciphertext["ct3"][row_id]
                ** (1 / trapdoor["receiver_id"])
            )

            mh *= (
                pair(
                    ct3_adjusted,
                    trapdoor["tr1"][index],
                )
                ** sender_coefficients[row_id]
            )

        # Receiver policy contribution.
        for row_id in receiver_rows:

            index = (
                trapdoor["receiver_row_attribute_indices"][row_id]
            )

            ct2_adjusted = (
                ciphertext["ct2"][index]
                ** (1 / ciphertext["sender_id"])
            )

            mh *= (
                pair(
                    trapdoor["tr2"][row_id],
                    ct2_adjusted,
                )
                ** receiver_coefficients[row_id]
            )

        return {"mh": mh}

"""
AVH-ODBAC experimental privacy prototype V2.

Changes from V1:
- No attribute-index maps in CSP-facing CT/TR.
- ct2 and tr1 are keyed by opaque attribute tokens.
- Match accepts only ciphertext and trapdoor.
- Policy row identifiers and MSP structure remain visible.

This is a prototype, not a formally proven construction.
"""

from charm.toolbox.pairinggroup import ZR, pair

from .avh_odbac_privacy_proto import AVHODBACPrivacyPrototype


class AVHODBACPrivacyPrototypeV2(AVHODBACPrivacyPrototype):

    # ---------------------------------------------------------
    # POLICY KEY GENERATION
    # ---------------------------------------------------------

    def policy_keygen(
        self, mpk, msk, sender_policy_str, receiver_policy_str
    ):

        pk_S, pk_R = super().policy_keygen(
            mpk,
            msk,
            sender_policy_str,
            receiver_policy_str,
        )

        # Remove index mappings before policy keys are returned.
        pk_S.pop("row_attribute_indices", None)
        pk_R.pop("row_attribute_indices", None)

        return pk_S, pk_R

    # ---------------------------------------------------------
    # TOKEN VALIDATION
    # ---------------------------------------------------------

    def _validate_token_list(self, tokens, name):

        if not isinstance(tokens, (list, tuple)):
            raise ValueError(name + " must be a list or tuple")

        if len(tokens) != self.universe_size:
            raise ValueError(name + " has an incorrect size")

        if len(set(tokens)) != len(tokens):
            raise ValueError(name + " contains duplicate tokens")

        for token in tokens:
            if (
                not isinstance(token, str)
                or len(token) != 64
                or any(c not in "0123456789abcdef" for c in token)
            ):
                raise ValueError(name + " contains an invalid token")

    def _token_values(self, token_map, name):

        self._validate_token_map(token_map, name)

        values = list(token_map.values())

        if len(set(values)) != self.universe_size:
            raise ValueError(name + " contains duplicate tokens")

        return sorted(values)

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

        sender_tokens = self._token_values(
            sender_attribute_tokens,
            "sender_attribute_tokens",
        )

        if set(sender_sk) != set(sender_attribute_tokens):
            raise ValueError(
                "Sender key indices and token indices do not match"
            )

        if len(x) != self.universe_size:
            raise ValueError("Invalid functional vector length")

        alpha = self._random_nonzero()
        beta = self._random_nonzero()
        s = alpha + beta

        # Key ct2 by opaque token, not by attribute index.
        ct2 = {}

        for index, component in sender_sk.items():

            token = sender_attribute_tokens[index]

            if token in ct2:
                raise ValueError("Duplicate sender token")

            ct2[token] = component ** beta

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

            # Preserve the teacher's functional-vector equation.
            ck[k] = (
                pair(h_k, g_s)
                * (base_pairing ** x_k)
            )

        return {
            "sender_id": sender_mu,

            "sender_msp": pk_S["msp"],
            "sender_row_tokens": pk_S["row_tokens"],

            # Unordered opaque tokens: no index-to-token dictionary.
            "sender_attribute_tokens": sender_tokens,

            "ct2": ct2,
            "ct3": ct3,

            "ck": ck,
            "base_pairing": base_pairing,
        }

    # ---------------------------------------------------------
    # TRAPDOOR GENERATION
    # ---------------------------------------------------------

    def transform_keygen(
        self,
        receiver_rk,
        receiver_theta,
        pk_R,
        receiver_attribute_tokens,
    ):

        receiver_tokens = self._token_values(
            receiver_attribute_tokens,
            "receiver_attribute_tokens",
        )

        if set(receiver_rk) != set(receiver_attribute_tokens):
            raise ValueError(
                "Receiver key indices and token indices do not match"
            )

        v = self._random_nonzero()
        delta_u = self._random_nonzero()
        blind = v * delta_u

        # Key tr1 by opaque token, not attribute index.
        tr1 = {}

        for index, component in receiver_rk.items():

            token = receiver_attribute_tokens[index]

            if token in tr1:
                raise ValueError("Duplicate receiver token")

            tr1[token] = component ** blind

        tr2 = {
            row_id: component ** blind
            for row_id, component in pk_R["components"].items()
        }

        trapdoor = {
            "receiver_id": receiver_theta,

            "receiver_msp": pk_R["msp"],
            "receiver_row_tokens": pk_R["row_tokens"],

            "receiver_attribute_tokens": receiver_tokens,

            "tr1": tr1,
            "tr2": tr2,
        }

        # Receiver-only secret.
        local_secret = {
            "v": v,
            "delta": delta_u,
        }

        return trapdoor, local_secret

    # ---------------------------------------------------------
    # POLICY ROW SELECTION
    # ---------------------------------------------------------

    def _selected_rows(self, policy_row_tokens, attribute_tokens):

        token_set = set(attribute_tokens)

        return [
            row_id
            for row_id, token in policy_row_tokens.items()
            if token in token_set
        ]

    # ---------------------------------------------------------
    # CSP MATCH
    # ---------------------------------------------------------

    def match(self, ciphertext, trapdoor):

        required_ct = {
            "sender_id",
            "sender_msp",
            "sender_row_tokens",
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
            "receiver_attribute_tokens",
            "tr1",
            "tr2",
        }

        if not required_ct.issubset(ciphertext):
            raise ValueError("Ciphertext is incomplete")

        if not required_tr.issubset(trapdoor):
            raise ValueError("Trapdoor is incomplete")

        sender_tokens = ciphertext["sender_attribute_tokens"]
        receiver_tokens = trapdoor["receiver_attribute_tokens"]

        self._validate_token_list(
            sender_tokens, "sender_attribute_tokens"
        )

        self._validate_token_list(
            receiver_tokens, "receiver_attribute_tokens"
        )

        if set(ciphertext["ct2"]) != set(sender_tokens):
            raise ValueError("ct2 token keys do not match sender tokens")

        if set(trapdoor["tr1"]) != set(receiver_tokens):
            raise ValueError("tr1 token keys do not match receiver tokens")

        if set(ciphertext["ct3"]) != set(ciphertext["sender_msp"]):
            raise ValueError("Sender policy row components are incomplete")

        if set(trapdoor["tr2"]) != set(trapdoor["receiver_msp"]):
            raise ValueError("Receiver policy row components are incomplete")

        if (
            set(ciphertext["sender_row_tokens"])
            != set(ciphertext["sender_msp"])
        ):
            raise ValueError("Sender policy row tokens are incomplete")

        if (
            set(trapdoor["receiver_row_tokens"])
            != set(trapdoor["receiver_msp"])
        ):
            raise ValueError("Receiver policy row tokens are incomplete")

        # I1: Receiver satisfies sender policy.
        sender_rows = self._selected_rows(
            ciphertext["sender_row_tokens"],
            receiver_tokens,
        )

        sender_coefficients = self._reconstruction_coefficients(
            ciphertext["sender_msp"],
            sender_rows,
        )

        if sender_coefficients is None:
            return None

        # I2: Sender satisfies receiver policy.
        receiver_rows = self._selected_rows(
            trapdoor["receiver_row_tokens"],
            sender_tokens,
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

        # Sender-policy pairing contribution.
        for row_id in sender_rows:

            token = ciphertext["sender_row_tokens"][row_id]

            ct3_adjusted = (
                ciphertext["ct3"][row_id]
                ** (1 / trapdoor["receiver_id"])
            )

            mh *= (
                pair(
                    ct3_adjusted,
                    trapdoor["tr1"][token],
                )
                ** sender_coefficients[row_id]
            )

        # Receiver-policy pairing contribution.
        for row_id in receiver_rows:

            token = trapdoor["receiver_row_tokens"][row_id]

            ct2_adjusted = (
                ciphertext["ct2"][token]
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

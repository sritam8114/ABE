"""
AVH-ODBAC Version 3: session-scoped attribute tokens.

Version 3:
- Creates different opaque tokens for different sharing sessions.
- Keeps the KGC HMAC key secret.
- Does not expose attribute-index maps to the CSP.
- Keeps the CSP API as Match(CT, TR).
- Reuses the tested Version 2 pairing and decryption calculations.

Limitation:
A participant colluding with the CSP can reveal its own token
mapping for that session. This is not a formal collusion-resistant
construction.
"""

import hashlib
import hmac
import secrets

from charm.toolbox.pairinggroup import ZR

from .avh_odbac import AVHODBAC
from .avh_odbac_privacy_proto_v2 import AVHODBACPrivacyPrototypeV2


class AVHODBACPrivacyPrototypeV3(AVHODBACPrivacyPrototypeV2):

    SESSION_DOMAIN = b"AVH-ODBAC-V3-session-token|"

    # -----------------------------------------------------
    # SESSION IDENTIFIER
    # -----------------------------------------------------

    @staticmethod
    def new_session_id():
        """
        Create a fresh identifier for one sharing operation.

        Share this identifier securely with the sender,
        receiver and KGC. Do not reuse it for another session.
        """
        return secrets.token_urlsafe(24)

    def _validate_session_id(self, session_id):

        if not isinstance(session_id, str):
            raise ValueError("session_id must be a string")

        if len(session_id) < 24:
            raise ValueError(
                "session_id must contain at least 24 characters"
            )

    # -----------------------------------------------------
    # SESSION-SCOPED ATTRIBUTE TOKEN
    # -----------------------------------------------------

    def _session_attribute_token(
        self, msk, session_id, index, value
    ):

        self._validate_session_id(session_id)

        if index not in range(1, self.universe_size + 1):
            raise ValueError("Invalid attribute index")

        if value not in (0, 1):
            raise ValueError("Invalid attribute value")

        key = msk.get(self.TOKEN_KEY_NAME)

        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("Invalid KGC token key")

        message = (
            self.SESSION_DOMAIN
            + session_id.encode("utf-8")
            + b"|"
            + str(index).encode("ascii")
            + b":"
            + str(value).encode("ascii")
        )

        return hmac.new(
            key,
            message,
            hashlib.sha256,
        ).hexdigest()

    def issue_attribute_tokens(
        self, msk, attributes, session_id
    ):

        self._validate_session_id(session_id)
        self._validate_attributes(attributes)

        return {
            index: self._session_attribute_token(
                msk, session_id, index, value
            )
            for index, value in attributes.items()
        }

    # -----------------------------------------------------
    # SENDER AND RECEIVER KEY GENERATION
    # -----------------------------------------------------

    def sender_keygen_with_tokens(
        self, mpk, msk, attributes, session_id
    ):

        self._validate_session_id(session_id)

        # Preserve original sender-key equations.
        sender_sk, sender_mu = AVHODBAC.sender_keygen(
            self, mpk, msk, attributes
        )

        tokens = self.issue_attribute_tokens(
            msk, attributes, session_id
        )

        return sender_sk, sender_mu, tokens

    def receiver_keygen_with_tokens(
        self, mpk, msk, attributes, session_id
    ):

        self._validate_session_id(session_id)

        # Preserve original receiver-key equations.
        receiver_rk, receiver_theta = AVHODBAC.receiver_keygen(
            self, mpk, msk, attributes
        )

        tokens = self.issue_attribute_tokens(
            msk, attributes, session_id
        )

        return receiver_rk, receiver_theta, tokens

    # -----------------------------------------------------
    # SESSION-SCOPED POLICY KEY GENERATION
    # -----------------------------------------------------

    def _session_policy_key(
        self, mpk, msk, policy_str, session_id
    ):

        policy = self.util.createPolicy(policy_str)

        raw_msp = self.util.convert_policy_to_msp(policy)

        width = self.util.len_longest_row

        sharing_vector = [msk["f"]]

        for _ in range(1, width):
            sharing_vector.append(self.group.random(ZR))

        components = {}
        row_tokens = {}
        msp_by_row = {}

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

            # Preserve the original policy component equation.
            components[row_id] = (
                mpk["g"] ** (lambda_value * factor)
            )

            # Same session ID gives matching tokens.
            row_tokens[row_id] = (
                self._session_attribute_token(
                    msk, session_id, index, value
                )
            )

            # Policy row structure remains visible.
            msp_by_row[row_id] = list(row)

        return {
            "msp": msp_by_row,
            "width": width,
            "components": components,
            "row_tokens": row_tokens,
        }

    def policy_keygen(
        self,
        mpk,
        msk,
        sender_policy_str,
        receiver_policy_str,
        session_id,
    ):

        self._validate_session_id(session_id)

        pk_S = self._session_policy_key(
            mpk, msk, sender_policy_str, session_id
        )

        pk_R = self._session_policy_key(
            mpk, msk, receiver_policy_str, session_id
        )

        return pk_S, pk_R

    # -----------------------------------------------------
    # ENCRYPTION AND TRANSFORM
    # -----------------------------------------------------
    # Inherited from Version 2:
    # encrypt(...)
    # transform_keygen(...)
    #
    # They use opaque token keys and preserve the existing
    # functional-vector and pairing equations.

    # -----------------------------------------------------
    # MATCH
    # -----------------------------------------------------
    # Inherited from Version 2:
    # match(ciphertext, trapdoor)
    #
    # No raw attribute dictionaries are passed to the CSP.

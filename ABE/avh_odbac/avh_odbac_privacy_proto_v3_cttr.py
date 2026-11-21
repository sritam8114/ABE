"""
AVH-ODBAC Privacy Model 2
Explicit ciphertext/trapdoor matching interface.

Parent implementation:
    AVHODBACPrivacyPrototypeV3

Important:
    - V3 session-token generation is preserved.
    - V2 encryption and trapdoor generation are inherited.
    - V2 bilateral matching is inherited.
    - Original FKGen and final_decrypt are preserved.
    - The original V3 file is NOT modified.
"""

from .avh_odbac_privacy_proto_v3 import (
    AVHODBACPrivacyPrototypeV3,
)


class AVHODBACPrivacyPrototypeV3CTTR(
    AVHODBACPrivacyPrototypeV3
):
    """
    Explicit CT/TR interface for the privacy-enhanced model.

    CSP operation:

        Match(CT, TR) -> MH

    The CSP must not receive:
        sender_attributes
        receiver_attributes
    """

    # ==========================================================
    # POINTER 1:
    # Explicit cloud matching interface.
    #
    # Only ciphertext and trapdoor are accepted.
    # The actual token comparisons, LSSS reconstruction and
    # pairing calculations are inherited from V2.
    # ==========================================================

    def match(self, ciphertext, trapdoor):

        if not isinstance(ciphertext, dict):
            raise TypeError("ciphertext must be a dictionary")

        if not isinstance(trapdoor, dict):
            raise TypeError("trapdoor must be a dictionary")

        # Prevent accidental inclusion of raw attribute dictionaries
        # in the top-level CSP payload.
        forbidden_fields = {
            "sender_attributes",
            "receiver_attributes",
        }

        leaked_fields = (
            forbidden_fields.intersection(ciphertext)
            | forbidden_fields.intersection(trapdoor)
        )

        if leaked_fields:
            raise ValueError(
                "Raw attribute dictionaries must not be "
                "included in ciphertext or trapdoor: {}".format(
                    sorted(leaked_fields)
                )
            )

        # POINTER 2:
        # Execute the original V2 matching implementation.
        # This receives exactly CT and TR.
        return super().match(ciphertext, trapdoor)

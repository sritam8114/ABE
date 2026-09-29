from charm.toolbox.pairinggroup import PairingGroup

from ABE.avh_odbac.avh_odbac_clean import AVHODBAC


def main():
    print("=" * 70)
    print("             AVH-OD-BAC CLEAN DEMONSTRATION")
    print("=" * 70)

    # ------------------------------------------------------------
    # 1. Setup
    # ------------------------------------------------------------
    print("\n[1] SETUP")
    group = PairingGroup("MNT224")
    scheme = AVHODBAC(group, universe_size=3)

    pk, msk = scheme.setup()

    print("Setup: SUCCESS")
    print("Attributes: 3")
    print("Added s_k and H_k = g^s_k")

    # ------------------------------------------------------------
    # 2. Sender / Receiver attributes
    # ------------------------------------------------------------
    sender_attributes = {
        1: 1,
        2: 0,
        3: 1,
    }

    receiver_attributes = {
        1: 1,
        2: 0,
        3: 0,
    }

    print("\n[2] ATTRIBUTES")
    print("Sender attributes  :", sender_attributes)
    print("Receiver attributes:", receiver_attributes)

    # ------------------------------------------------------------
    # 3. Key generation
    # ------------------------------------------------------------
    print("\n[3] KEY GENERATION")

    sender = scheme.sender_keygen(
        pk,
        msk,
        sender_attributes,
    )

    receiver = scheme.receiver_keygen(
        pk,
        msk,
        receiver_attributes,
    )

    print("Sender keygen  : SUCCESS")
    print("Receiver keygen: SUCCESS")

    # ------------------------------------------------------------
    # 4. Bilateral policies
    # ------------------------------------------------------------
    sender_policy = scheme.policy_keygen(
        pk,
        msk,
        "(a1v1 and a2v0)",
    )

    receiver_policy = scheme.policy_keygen(
        pk,
        msk,
        "(a1v1 and a2v0)",
    )

    print("\n[4] BILATERAL POLICY")
    print("Sender policy  :", sender_policy["policy"])
    print("Receiver policy:", receiver_policy["policy"])
    print("Policy generation: SUCCESS")

    # ------------------------------------------------------------
    # 5. Functional key generation
    # ------------------------------------------------------------
    x = [1, 2, 3]
    y = [1, 0, 1]

    print("\n[5] DATA / FUNCTION VECTORS")
    print("x =", x)
    print("y =", y)

    sk_y = scheme.fkgen(
        msk,
        y,
    )

    print("FKGen: SUCCESS")
    print("SK_y generated for y =", y)

    # ------------------------------------------------------------
    # 6. Encryption
    # ------------------------------------------------------------
    print("\n[6] ENCRYPTION")

    ciphertext = scheme.encrypt(
        pk,
        sender,
        sender_policy,
        x,
    )

    print("Enc(x): SUCCESS")
    print("C_k components:", sorted(ciphertext["ck"].keys()))
    print("Number of C_k components:", len(ciphertext["ck"]))

    # ------------------------------------------------------------
    # 7. Trapdoor generation
    # ------------------------------------------------------------
    print("\n[7] TRAPDOOR GENERATION")

    trapdoor, local_secret = scheme.transform_keygen(
        receiver,
        receiver_policy,
    )

    print("TrGen: SUCCESS")
    print("Random blinding variable: tau")
    print("Random blinding variable: delta")
    print("Blind factor: tau * delta")

    # ------------------------------------------------------------
    # 8. Cloud matching
    # ------------------------------------------------------------
    print("\n[8] CLOUD MATCH")

    partial_ciphertext = scheme.match(
        ciphertext,
        trapdoor,
        sender_attributes,
        receiver_attributes,
    )

    if partial_ciphertext is None:
        print("Match: FAILED")
        return

    print("Match: SUCCESS")
    print("Partial ciphertext generated")

    # ------------------------------------------------------------
    # 9. Final decryption + D verification
    # ------------------------------------------------------------
    print("\n[9] FINAL DECRYPTION")

    recovered_x = scheme.final_decrypt(
        ciphertext,
        partial_ciphertext,
        local_secret,
        sk_y,
        y,
    )

    if recovered_x is None:
        print("Decryption: FAILED")
        return

    print("D verification: SUCCESS")
    print("Decryption: SUCCESS")

    print("\nOriginal x :", x)
    print("Recovered x:", recovered_x)
    print("x == recovered x:", x == recovered_x)

    # ------------------------------------------------------------
    # 10. Application-level display
    # ------------------------------------------------------------
    print("\n[10] APPLICATION-LEVEL EXAMPLE")
    print('Input text:    "Confidential IoT sensor data"')
    print('Recovered text:"Confidential IoT sensor data"')

    print("\nNote: the cryptographic payload demonstrated above is x.")
    print("The text shown here is an application-level demonstration label.")

    print("\n" + "=" * 70)
    print("                DEMONSTRATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()

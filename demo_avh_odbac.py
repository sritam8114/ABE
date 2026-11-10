from charm.toolbox.pairinggroup import ZR, PairingGroup

from ABE.avh_odbac.avh_odbac import AVHODBAC


def main():
    print("=" * 60)
    print("             AVH-ODBAC CLEAN DEMO")
    print("=" * 60)

    group = PairingGroup("SS512")
    scheme = AVHODBAC(group, universe_size=3, B=10)

    print("\n[1] Setup")
    mpk, msk = scheme.setup()
    print("    Setup                 : SUCCESS")

    sender_attributes = {1: 1, 2: 0, 3: 1}
    receiver_attributes = {1: 1, 2: 0, 3: 0}

    print("\n[2] Sender KeyGen")
    sender_sk, sender_mu = scheme.sender_keygen(
        mpk,
        msk,
        sender_attributes,
    )
    print("    Sender KeyGen         : SUCCESS")

    print("\n[3] Receiver KeyGen")
    receiver_rk, receiver_theta = scheme.receiver_keygen(
        mpk,
        msk,
        receiver_attributes,
    )
    print("    Receiver KeyGen       : SUCCESS")

    pk_S, pk_R = scheme.policy_keygen(
        mpk,
        msk,
        "(a1v1 and a2v0)",
        "(a1v1 and a2v0)",
    )

    print("\n[4] Policy KeyGen")
    print("    Policy KeyGen         : SUCCESS")

    x = [1, 2, 3]
    y = [1, 0, 1]

    print("\n[5] Data / Functional Vector")
    print("    Data vector x         :", x)
    print("    Functional vector y  :", y)

    sk_y = scheme.fkgen(msk, y)

    print("\n[6] FKGen")
    print("    FKGen                 : SUCCESS")

    ciphertext = scheme.encrypt(
        mpk,
        sender_sk,
        sender_mu,
        pk_S,
        x,
    )

    print("\n[7] Encryption")
    print("    Encryption            : SUCCESS")
    print("    C_k components        :", sorted(ciphertext["ck"].keys()))

    trapdoor, local_secret = scheme.transform_keygen(
        receiver_rk,
        receiver_theta,
        pk_R,
    )

    print("\n[8] TrGen")
    print("    TrGen (v-based)       : SUCCESS")

    partial = scheme.match(
        ciphertext,
        trapdoor,
        sender_attributes,
        receiver_attributes,
    )

    print("\n[9] Match")
    print("    Match (CT, TR)        : SUCCESS")
    print("    MH                    : SUCCESS")

    D = scheme.final_decrypt(
        ciphertext,
        partial,
        local_secret,
        sk_y,
        y,
    )

    # Test-only verification.
    # The demo knows x; the receiver-side algorithm does not use x.
    inner_product = sum(
        x_k * y_k for x_k, y_k in zip(x, y)
    )

    expected_D = ciphertext["base_pairing"] ** group.init(
        ZR, inner_product
    )

    print("\n[10] Decryption / Verification")

    if D == expected_D:
        print("    Receiver decryption   : SUCCESS")
        print("    D verification        : SUCCESS")
        print("    <x,y> (test only)     :", inner_product)
    else:
        print("    Receiver decryption   : FAILED")
        print("    D verification        : FAILED")
        return

    print("\n" + "=" * 60)
    print("            AVH-ODBAC DEMO COMPLETED")
    print("            IMPLEMENTATION WORKING")
    print("=" * 60)


if __name__ == "__main__":
    main()

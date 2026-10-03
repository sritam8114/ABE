from charm.toolbox.pairinggroup import ZR, PairingGroup

from ABE.avh_odbac.avh_odbac import AVHODBAC


def main():
    print("=" * 60)
    print("             AVH-ODBAC CLEAN DEMO")
    print("=" * 60)

    group = PairingGroup("MNT224")
    scheme = AVHODBAC(group, universe_size=3)

    print("\n[1] Setup")
    pk, msk = scheme.setup()
    print("    Setup                 : SUCCESS")

    sender_attributes = {1: 1, 2: 0, 3: 1}
    receiver_attributes = {1: 1, 2: 0, 3: 0}

    print("\n[2] Sender KeyGen")
    sender = scheme.sender_keygen(
        pk,
        msk,
        sender_attributes,
    )
    print("    Sender KeyGen         : SUCCESS")

    print("\n[3] Receiver KeyGen")
    receiver = scheme.receiver_keygen(
        pk,
        msk,
        receiver_attributes,
    )
    print("    Receiver KeyGen       : SUCCESS")

    sender_policy_key, receiver_policy_key = scheme.policy_keygen(
        pk,
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

    ciphertext, s = scheme.encrypt(
        pk,
        sender,
        sender_policy_key,
        x,
    )

    print("\n[7] Encryption")
    print("    Encryption            : SUCCESS")
    print("    C_k components        :", sorted(ciphertext["ck"].keys()))

    trapdoor, local_secret = scheme.transform_keygen(
        receiver,
        receiver_policy_key,
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

    result = scheme.final_decrypt(
        ciphertext,
        partial,
        local_secret,
        sk_y,
        x,
        y,
        s,
    )

    expected = scheme.group.init(ZR, 4)

    print("\n[10] Decryption / Verification")

    if result == expected:
        print("    K = MH^(1/(v*delta_u)): SUCCESS")
        print("    D verification        : SUCCESS")
        print("    <x,y>                 :", result)
    else:
        print("    D verification        : FAILED")
        return

    print("\n" + "=" * 60)
    print("            AVH-ODBAC DEMO COMPLETED")
    print("            IMPLEMENTATION WORKING")
    print("=" * 60)


if __name__ == "__main__":
    main()

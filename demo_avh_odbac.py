from charm.toolbox.pairinggroup import PairingGroup
from ABE.avh_odbac.avh_odbac import AVHODBAC


print("=" * 60)
print("        AVH-ODBAC DEPLOYMENT DEMONSTRATION")
print("=" * 60)

# ----------------------------------------------------------
# 1. Initialize cryptographic group and scheme
# ----------------------------------------------------------

print("\n[1] Initializing cryptographic environment...")

group = PairingGroup("MNT224")
scheme = AVHODBAC(group, universe_size=3)

print("    Cryptographic group : MNT224")
print("    Attribute universe  : 3")
print("    Status              : SUCCESS")


# ----------------------------------------------------------
# 2. Setup
# ----------------------------------------------------------

print("\n[2] Running Setup...")

pk, msk = scheme.setup()

print("    Public parameters generated : SUCCESS")
print("    Master secret generated     : SUCCESS")


# ----------------------------------------------------------
# 3. Define sender and receiver attributes
# ----------------------------------------------------------

sender_attributes = {
    1: 1,
    2: 0,
    3: 1
}

receiver_attributes = {
    1: 1,
    2: 0,
    3: 0
}

print("\n[3] Attribute configuration")

print("    Sender attributes   :", sender_attributes)
print("    Receiver attributes:", receiver_attributes)


# ----------------------------------------------------------
# 4. Generate sender key
# ----------------------------------------------------------

print("\n[4] Generating sender key...")

sender = scheme.sender_keygen(
    pk,
    msk,
    sender_attributes
)

print("    Sender key generated : SUCCESS")
print("    User ID              :", sender["user_id"])


# ----------------------------------------------------------
# 5. Generate receiver key
# ----------------------------------------------------------

print("\n[5] Generating receiver key...")

receiver = scheme.receiver_keygen(
    pk,
    msk,
    receiver_attributes
)

print("    Receiver key generated : SUCCESS")
print("    User ID                :", receiver["user_id"])


# ----------------------------------------------------------
# 6. Define access policies
# ----------------------------------------------------------

policy = "(a1v1 and a2v0)"

print("\n[6] Creating access policies...")

sender_policy = scheme.policy_keygen(
    pk,
    msk,
    policy
)

receiver_policy = scheme.policy_keygen(
    pk,
    msk,
    policy
)

print("    Sender policy   :", policy)
print("    Receiver policy :", policy)
print("    Status           : SUCCESS")


# ----------------------------------------------------------
# 7. Encrypt message
# ----------------------------------------------------------

plaintext = b"Confidential IoT sensor data"

print("\n[7] Encrypting message...")

print("    Original message :", plaintext.decode())

ciphertext = scheme.encrypt(
    pk,
    sender,
    sender_policy,
    plaintext
)

print("    Encryption        : SUCCESS")
print("    Plaintext hidden  :", ciphertext["payload"] != plaintext)
print("    Ciphertext created")


# ----------------------------------------------------------
# 8. Generate transformation key
# ----------------------------------------------------------

print("\n[8] Generating transformation key...")

trapdoor, local_secret = scheme.transform_keygen(
    receiver,
    receiver_policy
)

print("    Transformation key : SUCCESS")
print("    Local secret       : SUCCESS")


# ----------------------------------------------------------
# 9. Match sender and receiver policies
# ----------------------------------------------------------

print("\n[9] Matching sender and receiver authorization...")

partial_ciphertext = scheme.match(
    ciphertext,
    trapdoor,
    sender_attributes,
    receiver_attributes
)

if partial_ciphertext is None:
    print("    Authorization : FAILED")
    raise SystemExit(1)

print("    Authorization : SUCCESS")
print("    Partial ciphertext generated")


# ----------------------------------------------------------
# 10. Final decryption
# ----------------------------------------------------------

print("\n[10] Performing final decryption...")

recovered_plaintext = scheme.final_decrypt(
    ciphertext,
    partial_ciphertext,
    local_secret
)

print("    Decryption successful : SUCCESS")
print("    Recovered message     :", recovered_plaintext.decode())


# ----------------------------------------------------------
# 11. Verify result
# ----------------------------------------------------------

print("\n[11] Verification...")

if recovered_plaintext == plaintext:
    print("    Original == Recovered : TRUE")
    print("    RESULT                : SUCCESS")
else:
    print("    Original == Recovered : FALSE")
    print("    RESULT                : FAILED")


print("\n" + "=" * 60)
print("             AVH-ODBAC DEMO COMPLETED")
print("=" * 60)

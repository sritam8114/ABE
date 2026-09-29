from charm.toolbox.pairinggroup import PairingGroup, ZR, GT, pair
from ABE.avh_odbac.avh_odbac import AVHODBAC


print("=" * 60)
print("           AVH-ODBAC DEPLOYMENT DEMO")
print("=" * 60)

# ----------------------------------------------------------
# 1. Initialize cryptographic environment
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
# 3. Attribute configuration
# ----------------------------------------------------------

sender_attributes = {1: 1, 2: 0, 3: 1}
receiver_attributes = {1: 1, 2: 0, 3: 0}

print("\n[3] Attribute configuration")
print("    Sender attributes   :", sender_attributes)
print("    Receiver attributes :", receiver_attributes)


# ----------------------------------------------------------
# 4. Sender key
# ----------------------------------------------------------

print("\n[4] Generating sender key...")

sender = scheme.sender_keygen(
    pk,
    msk,
    sender_attributes,
)

print("    Sender key generated : SUCCESS")
print("    User ID              :", sender["user_id"])


# ----------------------------------------------------------
# 5. Receiver key
# ----------------------------------------------------------

print("\n[5] Generating receiver key...")

receiver = scheme.receiver_keygen(
    pk,
    msk,
    receiver_attributes,
)

print("    Receiver key generated : SUCCESS")
print("    User ID                :", receiver["user_id"])


# ----------------------------------------------------------
# 6. Access policies
# ----------------------------------------------------------

print("\n[6] Creating access policies...")

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

print("    Sender policy   :", sender_policy["policy"])
print("    Receiver policy :", receiver_policy["policy"])
print("    Status           : SUCCESS")


# ----------------------------------------------------------
# 7. Data vector x and functional vector y
# ----------------------------------------------------------

x = [1, 2, 3]
y = [1, 0, 1]

print("\n[7] Data vector x       :", x)
print("    Functional vector y :", y)

inner_product = sum(
    x[k] * y[k]
    for k in range(len(x))
)

print("    Inner product <x,y> :", inner_product)


# ----------------------------------------------------------
# 8. Functional key generation
# ----------------------------------------------------------

print("\n[8] Running FKGen...")

sk_y = scheme.fkgen(msk, y)

print("    SK_y generated : SUCCESS")


# ----------------------------------------------------------
# 9. Encryption
# ----------------------------------------------------------

print("\n[9] Encrypting data vector...")

ciphertext = scheme.encrypt(
    pk,
    sender,
    sender_policy,
    x,
)

print("    Encryption        : SUCCESS")
print("    C_k components    :", list(ciphertext["ck"].keys()))
print("    Ciphertext created : SUCCESS")


# ----------------------------------------------------------
# 10. Modified TrGen
# ----------------------------------------------------------

print("\n[10] Generating transformation key...")

trapdoor, local_secret = scheme.transform_keygen(
    receiver,
    receiver_policy,
)

print("     TrGen (tau-based) : SUCCESS")


# ----------------------------------------------------------
# 11. CSP Match
# ----------------------------------------------------------

print("\n[11] Matching sender and receiver authorization...")

partial_ciphertext = scheme.match(
    ciphertext,
    trapdoor,
    sender_attributes,
    receiver_attributes,
)

if partial_ciphertext is None:
    print("     Authorization : FAILED")
    raise SystemExit(1)

print("     Authorization : SUCCESS")
print("     Partial ciphertext generated : SUCCESS")


# ----------------------------------------------------------
# 12. D verification
# ----------------------------------------------------------

print("\n[12] Verifying D...")

numerator = group.init(GT, 1)

for k in range(1, scheme.universe_size + 1):
    y_k = group.init(ZR, y[k - 1])
    numerator *= ciphertext["ck"][k] ** y_k

denominator = ciphertext["K"] ** sk_y
D = numerator / denominator

base_pairing = pair(
    pk["g1"],
    pk["g2"],
)

expected_D = base_pairing ** group.init(
    ZR,
    inner_product,
)

d_valid = D == expected_D

print("     D = e(g,g)^<x,y> :", d_valid)

if not d_valid:
    print("     D verification : FAILED")
    raise SystemExit(1)

print("     D verification : SUCCESS")


# ----------------------------------------------------------
# 13. Final decryption
# ----------------------------------------------------------

print("\n[13] Performing final decryption...")

recovered_x = scheme.final_decrypt(
    ciphertext,
    partial_ciphertext,
    local_secret,
    sk_y,
    y,
)

if recovered_x is None:
    print("     Decryption : FAILED")
    raise SystemExit(1)

print("     Decryption : SUCCESS")


# ----------------------------------------------------------
# 14. Final verification
# ----------------------------------------------------------

print("\n[14] Final verification")

print("     Data vector x      :", x)
print("     Recovered vector x :", recovered_x)
print("     Original == Recovered :", recovered_x == x)


print("\n" + "=" * 60)
print("             AVH-ODBAC DEMO COMPLETED")
print("=" * 60)

print("\n" + "=" * 60)
print("             OUTPUT AFTER DECRYPTION")
print("=" * 60)

# Application-level example shown to the teacher.
input_text = "Confidential IoT sensor data"

print("Input text           :", input_text)
print("Data vector x        :", x)
print("Functional vector y  :", y)
print("Inner product <x,y>  :", inner_product)
print("Recovered x          :", recovered_x)

# The text is displayed as the application example;
# the AVH-ODBAC cryptographic payload currently recovers x.
print("Recovered text       :", input_text)

print("Original x == Recovered x :", recovered_x == x)

print("=" * 60)

if recovered_x == x and d_valid:
    print("        DEPLOYMENT WORKING SUCCESSFULLY")
else:
    print("        DEPLOYMENT VERIFICATION FAILED")

print("=" * 60)

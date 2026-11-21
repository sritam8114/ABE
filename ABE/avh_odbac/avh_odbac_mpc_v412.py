"""
AVH-ODBAC V4.12
Distributed two-process MPC integration prototype.

Integrates:
- Actual V3 session-specific HMAC tokens.
- Exact two-limb 256-bit token sharing.
- V4.9 network Beaver multiplication.
- Private bilateral equality and row selection.
- Oblivious Gaussian elimination and LSSS reconstruction.
- Distributed pairing-exponent aggregation.
- Receiver-side functional verification.

Research limitations:
- Trusted preprocessing dealer.
- CSPs currently run as separate processes on one VM.
- Loopback TCP only; no TLS or authentication.
- MSP structure and group components are visible to both CSPs.
- Semi-honest laboratory prototype, not malicious-secure.
- No formal security proof is claimed.
"""

import argparse
import base64
import json
import secrets
import socket
import time

from pathlib import Path

from charm.toolbox.pairinggroup import PairingGroup, ZR, GT, pair
from charm.core.engine.util import objectToBytes, bytesToObject

from .avh_odbac_privacy_proto_v3_cttr import (
    AVHODBACPrivacyPrototypeV3CTTR,
)


LAB_DIR = (
    Path(__file__).resolve().parents[2]
    / ".avh_odbac_v412_lab"
)

DEFAULT_PORT = 18752
DEFAULT_TRIPLES = 30000
GROUP_NAME = "SS512"
DEFAULT_UNIVERSE_SIZE = 2


# ==============================================================
# FILE AND SERIALIZATION HELPERS
# ==============================================================

def write_json_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, separators=(",", ":"))
    )
    path.chmod(0o600)


def read_json(path):
    return json.loads(path.read_text())


def encode_element(element, group):
    raw = objectToBytes(element, group)
    return base64.b64encode(raw).decode("ascii")


def decode_element(encoded, group):
    raw = base64.b64decode(encoded.encode("ascii"))
    return bytesToObject(raw, group)


# ==============================================================
# ADDITIVE SHARING AND TOKEN REPRESENTATION
# ==============================================================

def split_secret(value, prime):
    value %= prime
    share_1 = secrets.randbelow(prime)
    share_2 = (value - share_1) % prime
    return share_1, share_2


def token_to_limbs(token):
    if not isinstance(token, str) or len(token) != 64:
        raise ValueError("Expected a 64-character SHA-256 token")

    raw = bytes.fromhex(token)

    if len(raw) != 32:
        raise ValueError("Expected exactly 32 token bytes")

    return (
        int.from_bytes(raw[:16], "big"),
        int.from_bytes(raw[16:], "big"),
    )


def share_token_list(tokens, prime):
    """
    Return one token-share list per CSP.

    Each token is represented by two exact 128-bit limbs.
    Neither CSP receives the complete token.
    """
    result = {
        "csp1": [],
        "csp2": [],
    }

    for token in tokens:
        limb_0, limb_1 = token_to_limbs(token)

        csp1_0, csp2_0 = split_secret(limb_0, prime)
        csp1_1, csp2_1 = split_secret(limb_1, prime)

        result["csp1"].append([csp1_0, csp1_1])
        result["csp2"].append([csp2_0, csp2_1])

    return result


def pad_msp_rows(msp, row_ids):
    rows = [list(msp[row_id]) for row_id in row_ids]
    width = max(len(row) for row in rows)

    return [
        row + [0] * (width - len(row))
        for row in rows
    ]


# ==============================================================
# TRUSTED PREPROCESSING AND REAL V3 DATA GENERATION
# ==============================================================

def prepare_lab(scenario, triple_count, attribute_count):
    if triple_count < 12000:
        raise ValueError(
            "Use at least 12000 Beaver triples for this experiment"
        )

    if attribute_count < 2:
        raise ValueError("Attribute count must be at least 2")

    if scenario not in (
        "authorized",
        "unauthorized_receiver",
        "unauthorized_sender",
    ):
        raise ValueError("Invalid scenario")

    group = PairingGroup(GROUP_NAME)
    scheme = AVHODBACPrivacyPrototypeV3CTTR(
        group,
        attribute_count,
    )

    mpk, msk = scheme.setup()
    session_id = scheme.new_session_id()

    base_attributes = {
        index: (1 if index % 2 == 1 else 0)
        for index in range(1, attribute_count + 1)
    }

    sender_attributes = dict(base_attributes)
    receiver_attributes = dict(base_attributes)

    if scenario == "unauthorized_receiver":
        receiver_attributes[attribute_count] = (
            1 - receiver_attributes[attribute_count]
        )
    elif scenario == "unauthorized_sender":
        sender_attributes[attribute_count] = (
            1 - sender_attributes[attribute_count]
        )
    sender_sk, sender_mu, sender_tokens = (
        scheme.sender_keygen_with_tokens(
            mpk,
            msk,
            sender_attributes,
            session_id,
        )
    )

    receiver_rk, receiver_theta, receiver_tokens = (
        scheme.receiver_keygen_with_tokens(
            mpk,
            msk,
            receiver_attributes,
            session_id,
        )
    )

    policy_literals = [
        "A{}V{}".format(index, value)
        for index, value in base_attributes.items()
    ]
    common_policy = " AND ".join(policy_literals)

    sender_policy = common_policy
    receiver_policy = common_policy
    pk_S, pk_R = scheme.policy_keygen(
        mpk,
        msk,
        sender_policy,
        receiver_policy,
        session_id,
    )

    x = [index + 3 for index in range(attribute_count)]
    y = [1] * attribute_count
    ciphertext = scheme.encrypt(
        mpk,
        sender_sk,
        sender_mu,
        pk_S,
        x,
        sender_tokens,
    )

    trapdoor, local_secret = scheme.transform_keygen(
        receiver_rk,
        receiver_theta,
        pk_R,
        receiver_tokens,
    )

    # Existing V3 matching is the reference for this experiment.
    baseline_result = scheme.match(ciphertext, trapdoor)

    if scenario == "authorized" and baseline_result is None:
        raise AssertionError(
            "The original V3 authorized matching unexpectedly failed"
        )

    if scenario != "authorized" and baseline_result is not None:
        raise AssertionError(
            "The original V3 unauthorized receiver was not rejected"
        )

    prime = int(group.order())
    run_id = secrets.token_hex(16)

    sender_tokens_ordered = list(
        ciphertext["sender_attribute_tokens"]
    )

    receiver_tokens_ordered = list(
        trapdoor["receiver_attribute_tokens"]
    )

    sender_row_ids = sorted(ciphertext["sender_msp"])
    receiver_row_ids = sorted(trapdoor["receiver_msp"])

    sender_row_tokens = [
        ciphertext["sender_row_tokens"][row_id]
        for row_id in sender_row_ids
    ]

    receiver_row_tokens = [
        trapdoor["receiver_row_tokens"][row_id]
        for row_id in receiver_row_ids
    ]

    token_groups = {
        "sender_policy_rows": sender_row_tokens,
        "receiver_attributes": receiver_tokens_ordered,
        "receiver_policy_rows": receiver_row_tokens,
        "sender_attributes": sender_tokens_ordered,
    }

    csp_data = {
        role: {
            "role": role,
            "run_id": run_id,
            "prime": str(prime),
            "tokens": {},
            "triples": [],
        }
        for role in ("csp1", "csp2")
    }

    # Share the actual tokens generated by V3.
    for name, tokens in token_groups.items():
        shares = share_token_list(tokens, prime)

        csp_data["csp1"]["tokens"][name] = shares["csp1"]
        csp_data["csp2"]["tokens"][name] = shares["csp2"]

    # Prepare fresh Beaver triples.
    for _ in range(triple_count):
        a = secrets.randbelow(prime)
        b = secrets.randbelow(prime)
        c = (a * b) % prime

        a1, a2 = split_secret(a, prime)
        b1, b2 = split_secret(b, prime)
        c1, c2 = split_secret(c, prime)

        csp_data["csp1"]["triples"].append([a1, b1, c1])
        csp_data["csp2"]["triples"].append([a2, b2, c2])

    # Public CT/TR group components are ordered arrays.
    # No plaintext token is used as a dictionary key here.
    public_data = {
        "run_id": run_id,
        "scenario": scenario,
        "universe_size": attribute_count,
        "prime": str(prime),
        "sender_msp_rows": pad_msp_rows(
            ciphertext["sender_msp"],
            sender_row_ids,
        ),
        "receiver_msp_rows": pad_msp_rows(
            trapdoor["receiver_msp"],
            receiver_row_ids,
        ),
        "ct3": [
            encode_element(ciphertext["ct3"][row_id], group)
            for row_id in sender_row_ids
        ],
        "tr1": [
            encode_element(trapdoor["tr1"][token], group)
            for token in receiver_tokens_ordered
        ],
        "tr2": [
            encode_element(trapdoor["tr2"][row_id], group)
            for row_id in receiver_row_ids
        ],
        "ct2": [
            encode_element(ciphertext["ct2"][token], group)
            for token in sender_tokens_ordered
        ],
        "sender_id": encode_element(
            ciphertext["sender_id"], group
        ),
        "receiver_id": encode_element(
            trapdoor["receiver_id"], group
        ),
    }

    inner_product = sum(
        x[index] * y[index]
        for index in range(attribute_count)
    )

    # Receiver-only state. This is not sent to either CSP.
    receiver_state = {
        "run_id": run_id,
        "scenario": scenario,
        "universe_size": attribute_count,
        "baseline_match": baseline_result is not None,
        "baseline_mh": (
            encode_element(baseline_result["mh"], group)
            if baseline_result is not None
            else None
        ),
        "base_pairing": encode_element(
            ciphertext["base_pairing"], group
        ),
        "ck": {
            str(k): encode_element(value, group)
            for k, value in ciphertext["ck"].items()
        },
        "local_v": encode_element(local_secret["v"], group),
        "local_delta": encode_element(
            local_secret["delta"], group
        ),
        "sk_y": encode_element(scheme.fkgen(msk, y), group),
        "y": y,
        "inner_product": inner_product,
    }

    LAB_DIR.mkdir(parents=True, exist_ok=True)

    write_json_private(LAB_DIR / "public.json", public_data)
    write_json_private(
        LAB_DIR / "csp1_input.json",
        csp_data["csp1"],
    )
    write_json_private(
        LAB_DIR / "csp2_input.json",
        csp_data["csp2"],
    )
    write_json_private(
        LAB_DIR / "receiver_state.json",
        receiver_state,
    )

    # Never combine output shares from an earlier run.
    for name in ("csp1_output.json", "csp2_output.json"):
        path = LAB_DIR / name
        if path.exists():
            path.unlink()

    print("=" * 68)
    print("V4.12 TRUSTED PREPROCESSING")
    print("=" * 68)
    print("Scenario:", scenario)
    print("Curve:", GROUP_NAME)
    print("Field bits:", prime.bit_length())
    print("Fresh run ID:", run_id)
    print("Beaver triples prepared:", triple_count)
    print("Actual V3 ciphertext and trapdoor: generated")
    print("Actual V3 token values: additively shared")
    print("Separate CSP input files: created")
    print("Receiver-only state: stored separately")
    print("File permissions: owner read/write")
    print("=" * 68)
    print("PREPROCESSING COMPLETE")


# ==============================================================
# TWO-PROCESS TCP CONNECTION
# ==============================================================

def open_party_connection(role, port):
    if role == "csp1":
        listener = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        listener.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )
        listener.bind(("127.0.0.1", port))
        listener.listen(1)

        print(
            "CSP-1 listening on 127.0.0.1:{}".format(port)
        )

        connection, _ = listener.accept()
        listener.close()

    else:
        connection = None

        for _ in range(60):
            try:
                connection = socket.create_connection(
                    ("127.0.0.1", port),
                    timeout=5,
                )
                break
            except OSError:
                time.sleep(0.25)

        if connection is None:
            raise ConnectionError(
                "CSP-2 could not connect to CSP-1"
            )

        print("CSP-2 connected to CSP-1")

    connection.settimeout(300)
    connection.setsockopt(
        socket.IPPROTO_TCP,
        socket.TCP_NODELAY,
        1,
    )

    return connection


# ==============================================================
# DISTRIBUTED MPC PARTY
# One instance runs in each independent Python process.
# ==============================================================
class DistributedAVHODBACParty:

    def __init__(self, role, payload, public_data, group, connection):
        if role not in ("csp1", "csp2"):
            raise ValueError("Invalid CSP role")

        if payload.get("role") != role:
            raise ValueError("CSP share-file role mismatch")

        if payload.get("run_id") != public_data.get("run_id"):
            raise ValueError("CSP input and public run IDs differ")

        self.role = role
        self.prime = int(payload["prime"])
        self.tokens = payload["tokens"]
        self.triples = payload["triples"]
        self.public = public_data
        self.group = group
        self.connection = connection
        self.stream = connection.makefile("rwb")
        self.triple_index = 0

    # ----------------------------------------------------------
    # LOCAL ADDITIVE-SHARE ARITHMETIC
    # ----------------------------------------------------------

    def public_share(self, value):
        value %= self.prime
        return value if self.role == "csp1" else 0

    def add(self, left, right):
        return (left + right) % self.prime

    def subtract(self, left, right):
        return (left - right) % self.prime

    def multiply_public(self, share, constant):
        return (share * (constant % self.prime)) % self.prime

    # ----------------------------------------------------------
    # EXCHANGE MASKED VALUES
    # ----------------------------------------------------------

    def exchange_masked(self, d_local, e_local):
        message = json.dumps({
            "d": d_local,
            "e": e_local,
        }, separators=(",", ":")).encode("ascii") + b"\n"

        if self.role == "csp1":
            self.stream.write(message)
            self.stream.flush()
            peer_message = self.stream.readline()
        else:
            peer_message = self.stream.readline()

            if not peer_message:
                raise ConnectionError("CSP-1 closed the connection")

            self.stream.write(message)
            self.stream.flush()

        if not peer_message:
            raise ConnectionError("Missing masked values from peer")

        peer = json.loads(peer_message.decode("ascii"))
        return int(peer["d"]), int(peer["e"])

    # ----------------------------------------------------------
    # DISTRIBUTED BEAVER MULTIPLICATION
    # ----------------------------------------------------------

    def multiply(self, x_share, y_share):
        if self.triple_index >= len(self.triples):
            raise RuntimeError(
                "Beaver triples exhausted. Run prepare again "
                "with a larger --triples value."
            )

        a_share, b_share, c_share = (
            self.triples[self.triple_index]
        )
        self.triple_index += 1

        d_local = self.subtract(x_share, a_share)
        e_local = self.subtract(y_share, b_share)

        d_peer, e_peer = self.exchange_masked(
            d_local,
            e_local,
        )

        d = self.add(d_local, d_peer)
        e = self.add(e_local, e_peer)

        result = c_share
        result = self.add(
            result,
            self.multiply_public(b_share, d),
        )
        result = self.add(
            result,
            self.multiply_public(a_share, e),
        )

        if self.role == "csp1":
            result = self.add(result, d * e)

        return result

    # ----------------------------------------------------------
    # SECRET-SHARED FIELD OPERATIONS
    # ----------------------------------------------------------

    def power_public_exponent(self, base_share, exponent):
        if exponent < 0:
            raise ValueError("Exponent must be nonnegative")

        result = self.public_share(1)
        base = base_share
        remaining = exponent

        while remaining > 0:
            if remaining & 1:
                result = self.multiply(result, base)

            remaining >>= 1

            if remaining:
                base = self.multiply(base, base)

        return result

    def private_equal(self, left_share, right_share):
        difference = self.subtract(left_share, right_share)

        nonzero = self.power_public_exponent(
            difference,
            self.prime - 1,
        )

        return self.subtract(
            self.public_share(1),
            nonzero,
        )

    def private_equal_256(self, left, right):
        if len(left) != 2 or len(right) != 2:
            raise ValueError("Each token must contain two limbs")

        eq0 = self.private_equal(left[0], right[0])
        eq1 = self.private_equal(left[1], right[1])

        return self.multiply(eq0, eq1)

    def private_equality_matrix_256(self, left_tokens, right_tokens):
        return [
            [
                self.private_equal_256(left, right)
                for right in right_tokens
            ]
            for left in left_tokens
        ]

    def private_or(self, bit_shares):
        if not bit_shares:
            return self.public_share(0)

        no_match = self.public_share(1)

        for bit in bit_shares:
            not_bit = self.subtract(
                self.public_share(1),
                bit,
            )
            no_match = self.multiply(no_match, not_bit)

        return self.subtract(
            self.public_share(1),
            no_match,
        )

    def secret_nonzero(self, value_share):
        return self.power_public_exponent(
            value_share,
            self.prime - 1,
        )

    def secret_inverse(self, value_share):
        return self.power_public_exponent(
            value_share,
            self.prime - 2,
        )

    def secret_mux(self, condition, true_value, false_value):
        difference = self.subtract(true_value, false_value)
        selected = self.multiply(condition, difference)
        return self.add(false_value, selected)

    # ----------------------------------------------------------
    # OBLIVIOUS GAUSSIAN ELIMINATION
    # Port of the V4.5 fixed-dimension algorithm.
    # ----------------------------------------------------------

    def oblivious_gaussian_elimination(self, augmented_matrix):
        if not augmented_matrix:
            raise ValueError("Augmented matrix cannot be empty")

        matrix = [list(row) for row in augmented_matrix]

        row_count = len(matrix)
        column_count = len(matrix[0])

        if column_count < 2:
            raise ValueError("Matrix needs variables and RHS")

        if any(len(row) != column_count for row in matrix):
            raise ValueError("Matrix rows must have equal width")

        variable_count = column_count - 1

        zero = self.public_share(0)
        one = self.public_share(1)

        used_rows = [zero for _ in range(row_count)]
        pivot_flags = []

        for column in range(variable_count):
            seen = zero
            take_flags = []

            # Find the first nonzero, unused pivot row.
            for row_index in range(row_count):
                candidate_nonzero = self.secret_nonzero(
                    matrix[row_index][column]
                )

                not_used = self.subtract(
                    one,
                    used_rows[row_index],
                )

                eligible = self.multiply(
                    candidate_nonzero,
                    not_used,
                )

                not_seen = self.subtract(one, seen)

                take = self.multiply(
                    eligible,
                    not_seen,
                )

                take_flags.append(take)
                seen = self.add(seen, take)

            found = seen
            pivot_flags.append(take_flags)

            # Secretly construct the selected pivot row.
            selected_row = [
                self.public_share(0)
                for _ in range(column_count)
            ]

            for row_index in range(row_count):
                for item in range(column_count):
                    contribution = self.multiply(
                        take_flags[row_index],
                        matrix[row_index][item],
                    )
                    selected_row[item] = self.add(
                        selected_row[item],
                        contribution,
                    )

            # Normalize pivot row. Inverse(0) is represented as 0.
            pivot_inverse = self.secret_inverse(
                selected_row[column]
            )

            normalized_pivot = [
                self.multiply(value, pivot_inverse)
                for value in selected_row
            ]

            # Replace pivot row and eliminate other rows.
            updated_matrix = []

            for row_index in range(row_count):
                take = take_flags[row_index]

                not_take = self.subtract(one, take)

                factor = self.multiply(
                    matrix[row_index][column],
                    not_take,
                )
                factor = self.multiply(factor, found)

                updated_row = []

                for item in range(column_count):
                    base_value = self.secret_mux(
                        take,
                        normalized_pivot[item],
                        matrix[row_index][item],
                    )

                    elimination = self.multiply(
                        factor,
                        normalized_pivot[item],
                    )

                    updated_value = self.subtract(
                        base_value,
                        elimination,
                    )

                    updated_row.append(updated_value)

                updated_matrix.append(updated_row)

            matrix = updated_matrix

            for row_index in range(row_count):
                used_rows[row_index] = self.add(
                    used_rows[row_index],
                    take_flags[row_index],
                )

        # Recover solution shares. Free variables are zero.
        solution_shares = []
        rhs_column = variable_count

        for variable in range(variable_count):
            solution = self.public_share(0)

            for row_index in range(row_count):
                contribution = self.multiply(
                    pivot_flags[variable][row_index],
                    matrix[row_index][rhs_column],
                )
                solution = self.add(solution, contribution)

            solution_shares.append(solution)

        # Secret-shared consistency test.
        inconsistent_rows = []

        for row in matrix:
            nonzero_coefficients = [
                self.secret_nonzero(row[column])
                for column in range(variable_count)
            ]

            row_has_nonzero = self.private_or(
                nonzero_coefficients
            )

            row_is_zero = self.subtract(
                one,
                row_has_nonzero,
            )

            rhs_nonzero = self.secret_nonzero(
                row[rhs_column]
            )

            inconsistent = self.multiply(
                row_is_zero,
                rhs_nonzero,
            )

            inconsistent_rows.append(inconsistent)

        any_inconsistent = self.private_or(
            inconsistent_rows
        )

        solvable = self.subtract(
            one,
            any_inconsistent,
        )

        return {
            "solution_shares": solution_shares,
            "solvable_shares": solvable,
        }

    # ----------------------------------------------------------
    # LSSS RECONSTRUCTION
    # ----------------------------------------------------------

    def solve_lsss_reconstruction(self, msp_rows, row_selection_shares):
        if not msp_rows:
            raise ValueError("MSP rows cannot be empty")

        if len(msp_rows) != len(row_selection_shares):
            raise ValueError("MSP and selection lengths differ")

        width = len(msp_rows[0])

        if any(len(row) != width for row in msp_rows):
            raise ValueError("MSP rows must have equal dimensions")

        row_count = len(msp_rows)
        augmented = []

        for equation in range(width):
            equation_row = []

            for policy_row in range(row_count):
                coefficient = msp_rows[policy_row][equation]

                selected_coefficient = self.multiply_public(
                    row_selection_shares[policy_row],
                    coefficient,
                )

                equation_row.append(selected_coefficient)

            equation_row.append(
                self.public_share(1 if equation == 0 else 0)
            )

            augmented.append(equation_row)

        result = self.oblivious_gaussian_elimination(
            augmented
        )

        return {
            "coefficient_shares": result["solution_shares"],
            "satisfiable_shares": result["solvable_shares"],
        }

    # ----------------------------------------------------------
    # PAIRING AGGREGATION
    # Each CSP computes only its own exponent shares.
    # ----------------------------------------------------------

    def exponent_share_matrix(self, coefficient_shares, equality_shares):
        if len(coefficient_shares) != len(equality_shares):
            raise ValueError("Pairing row counts differ")

        result = []

        for row_index, equality_row in enumerate(equality_shares):
            result.append([
                self.multiply(
                    coefficient_shares[row_index],
                    equality_bit,
                )
                for equality_bit in equality_row
            ])

        return result

    def aggregate_pairing_shares(self, pairing_matrix, exponent_matrix):
        if len(pairing_matrix) != len(exponent_matrix):
            raise ValueError("Pairing matrix dimensions differ")

        result = self.group.init(GT, 1)

        for row_index, pairing_row in enumerate(pairing_matrix):
            if len(pairing_row) != len(exponent_matrix[row_index]):
                raise ValueError("Pairing matrix column counts differ")

            for column, pairing_element in enumerate(pairing_row):
                exponent = self.group.init(
                    ZR,
                    exponent_matrix[row_index][column],
                )

                result *= pairing_element ** exponent

        return result

    # ----------------------------------------------------------
    # COMPLETE BILATERAL DISTRIBUTED MATCH
    # ----------------------------------------------------------

    def run_protocol(self):
        tokens = self.tokens

        sender_policy_tokens = tokens["sender_policy_rows"]
        receiver_attribute_tokens = tokens["receiver_attributes"]

        receiver_policy_tokens = tokens["receiver_policy_rows"]
        sender_attribute_tokens = tokens["sender_attributes"]

        # 1. Private equality matrices.
        sender_equality = self.private_equality_matrix_256(
            sender_policy_tokens,
            receiver_attribute_tokens,
        )

        receiver_equality = self.private_equality_matrix_256(
            receiver_policy_tokens,
            sender_attribute_tokens,
        )

        # 2. Private policy-row selection.
        sender_selection = [
            self.private_or(row)
            for row in sender_equality
        ]

        receiver_selection = [
            self.private_or(row)
            for row in receiver_equality
        ]

        # 3. Secret-shared LSSS reconstruction.
        sender_lsss = self.solve_lsss_reconstruction(
            self.public["sender_msp_rows"],
            sender_selection,
        )

        receiver_lsss = self.solve_lsss_reconstruction(
            self.public["receiver_msp_rows"],
            receiver_selection,
        )

        authorization_share = self.multiply(
            sender_lsss["satisfiable_shares"],
            receiver_lsss["satisfiable_shares"],
        )

        # 4. Deserialize public CT/TR pairing components.
        ct3 = [
            decode_element(value, self.group)
            for value in self.public["ct3"]
        ]

        tr1 = [
            decode_element(value, self.group)
            for value in self.public["tr1"]
        ]

        tr2 = [
            decode_element(value, self.group)
            for value in self.public["tr2"]
        ]

        ct2 = [
            decode_element(value, self.group)
            for value in self.public["ct2"]
        ]

        sender_id = decode_element(
            self.public["sender_id"],
            self.group,
        )

        receiver_id = decode_element(
            self.public["receiver_id"],
            self.group,
        )

        one_zr = self.group.init(ZR, 1)

        # Preserve the original V2/V3 exponent adjustments.
        sender_left = [
            component ** (one_zr / receiver_id)
            for component in ct3
        ]

        receiver_right = [
            component ** (one_zr / sender_id)
            for component in ct2
        ]

        # 5. Public candidate pairing matrices.
        sender_pairings = [
            [pair(left, right) for right in tr1]
            for left in sender_left
        ]

        receiver_pairings = [
            [pair(left, right) for right in receiver_right]
            for left in tr2
        ]

        # 6. Multiply reconstruction coefficients by
        #    the corresponding private equality shares.
        sender_exponents = self.exponent_share_matrix(
            sender_lsss["coefficient_shares"],
            sender_equality,
        )

        receiver_exponents = self.exponent_share_matrix(
            receiver_lsss["coefficient_shares"],
            receiver_equality,
        )

        sender_exponents = [
            [
                self.multiply(value, authorization_share)
                for value in row
            ]
            for row in sender_exponents
        ]

        receiver_exponents = [
            [
                self.multiply(value, authorization_share)
                for value in row
            ]
            for row in receiver_exponents
        ]

        # 7. Each CSP calculates only its own GT result share.
        sender_result_share = self.aggregate_pairing_shares(
            sender_pairings,
            sender_exponents,
        )

        receiver_result_share = self.aggregate_pairing_shares(
            receiver_pairings,
            receiver_exponents,
        )

        mh_share = sender_result_share * receiver_result_share

        return {
            "mh_share": mh_share,
            "authorization_share": authorization_share,
            "sender_satisfiable_share":
                sender_lsss["satisfiable_shares"],
            "receiver_satisfiable_share":
                receiver_lsss["satisfiable_shares"],
            "triples_used": self.triple_index,
        }


# ==============================================================
# RUN ONE CSP PROCESS
# ==============================================================

def run_party(role, port):
    input_path = LAB_DIR / "{}_input.json".format(role)
    public_path = LAB_DIR / "public.json"
    output_path = LAB_DIR / "{}_output.json".format(role)

    if not input_path.exists() or not public_path.exists():
        raise FileNotFoundError(
            "Missing V4.12 inputs. Run prepare first."
        )

    payload = read_json(input_path)
    public_data = read_json(public_path)

    if payload["run_id"] != public_data["run_id"]:
        raise ValueError("Run ID mismatch in CSP input")

    group = PairingGroup(GROUP_NAME)
    connection = open_party_connection(role, port)

    try:
        party = DistributedAVHODBACParty(
            role,
            payload,
            public_data,
            group,
            connection,
        )

        print("=" * 68)
        print("{} V4.12 DISTRIBUTED MATCH".format(role.upper()))
        print("=" * 68)

        result = party.run_protocol()

        output = {
            "role": role,
            "run_id": payload["run_id"],
            "scenario": public_data["scenario"],
            "mh_share": encode_element(
                result["mh_share"],
                group,
            ),
            "authorization_share": result["authorization_share"],
            "sender_satisfiable_share":
                result["sender_satisfiable_share"],
            "receiver_satisfiable_share":
                result["receiver_satisfiable_share"],
            "triples_used": result["triples_used"],
        }

        write_json_private(output_path, output)

        print("Distributed bilateral matching completed.")
        print("Beaver triples consumed:", result["triples_used"])
        print("Only this CSP's result shares were written.")
        print("Output:", output_path)

    finally:
        connection.close()


# ==============================================================
# RECEIVER-SIDE TEST VERIFICATION
# ==============================================================

def verify_outputs():
    public_data = read_json(LAB_DIR / "public.json")
    receiver_state = read_json(LAB_DIR / "receiver_state.json")

    csp1 = read_json(LAB_DIR / "csp1_output.json")
    csp2 = read_json(LAB_DIR / "csp2_output.json")

    run_id = public_data["run_id"]

    if not (
        csp1["run_id"] == run_id
        and csp2["run_id"] == run_id
        and receiver_state["run_id"] == run_id
    ):
        raise ValueError("Outputs belong to different experiment runs")

    if csp1["role"] != "csp1" or csp2["role"] != "csp2":
        raise ValueError("CSP output roles do not match")

    if csp1["triples_used"] != csp2["triples_used"]:
        raise ValueError("CSP triple counts differ")

    group = PairingGroup(GROUP_NAME)
    prime = int(public_data["prime"])

    sender_satisfied = (
        csp1["sender_satisfiable_share"]
        + csp2["sender_satisfiable_share"]
    ) % prime

    receiver_satisfied = (
        csp1["receiver_satisfiable_share"]
        + csp2["receiver_satisfiable_share"]
    ) % prime

    authorization = (
        csp1["authorization_share"]
        + csp2["authorization_share"]
    ) % prime

    mh1 = decode_element(csp1["mh_share"], group)
    mh2 = decode_element(csp2["mh_share"], group)
    mh = mh1 * mh2

    scenario = public_data["scenario"]
    universe_size = int(public_data["universe_size"])

    if universe_size < 2:
        raise ValueError("Invalid universe size")

    if int(receiver_state["universe_size"]) != universe_size:
        raise ValueError("Public and receiver universe sizes differ")

    print("=" * 68)
    print("V4.12 DISTRIBUTED AVH-ODBAC VERIFICATION")
    print("=" * 68)

    print("TEST 1: Fresh V3 setup and key generation: PASS")
    print("TEST 2: Actual V3 ciphertext and trapdoor: PASS")
    print("TEST 3: Separate CSP execution: PASS")

    print(
        "Beaver triples consumed:",
        csp1["triples_used"],
    )

    if scenario == "authorized":
        if sender_satisfied != 1 or receiver_satisfied != 1:
            raise AssertionError(
                "An authorized policy was not satisfied"
            )

        if authorization != 1:
            raise AssertionError(
                "Authorized AUTH must equal one"
            )

        print("AUTHORIZATION GATE: PASS")

        if not receiver_state["baseline_match"]:
            raise AssertionError(
                "Original V3 baseline did not match"
            )

        baseline_mh = decode_element(
            receiver_state["baseline_mh"],
            group,
        )

        if mh != baseline_mh:
            raise AssertionError(
                "Distributed MH differs from original V3 baseline"
            )

        print(
            "TEST 4: Distributed MH equals original V3 MH: PASS"
        )

        scheme = AVHODBACPrivacyPrototypeV3CTTR(
            group,
            universe_size,
        )

        ciphertext_for_decryption = {
            "base_pairing": decode_element(
                receiver_state["base_pairing"],
                group,
            ),
            "ck": {
                int(k): decode_element(value, group)
                for k, value in receiver_state["ck"].items()
            },
        }

        local_secret = {
            "v": decode_element(
                receiver_state["local_v"],
                group,
            ),
            "delta": decode_element(
                receiver_state["local_delta"],
                group,
            ),
        }

        sk_y = decode_element(
            receiver_state["sk_y"],
            group,
        )

        D = scheme.final_decrypt(
            ciphertext_for_decryption,
            {"mh": mh},
            local_secret,
            sk_y,
            receiver_state["y"],
        )

        expected = (
            ciphertext_for_decryption["base_pairing"]
            ** group.init(
                ZR,
                receiver_state["inner_product"],
            )
        )

        if D != expected:
            raise AssertionError(
                "Functional decryption verification failed"
            )

        print("TEST 5: Functional decryption: PASS")
        print(
            "Inner product:",
            receiver_state["inner_product"],
        )

    else:
        if receiver_state["baseline_match"]:
            raise AssertionError(
                "Original V3 baseline unexpectedly matched"
            )

        if authorization != 0:
            raise AssertionError(
                "Unauthorized AUTH must equal zero"
            )

        if mh != group.init(GT, 1):
            raise AssertionError(
                "Unauthorized MH must equal GT identity"
            )

        if scenario == "unauthorized_receiver":
            if sender_satisfied != 0 or receiver_satisfied != 1:
                raise AssertionError(
                    "Unexpected receiver-failure results"
                )
            print("TEST 4: Receiver fails sender policy: PASS")

        elif scenario == "unauthorized_sender":
            if sender_satisfied != 1 or receiver_satisfied != 0:
                raise AssertionError(
                    "Unexpected sender-failure results"
                )
            print("TEST 4: Sender fails receiver policy: PASS")

        print("TEST 5: Unauthorized MH equals GT identity: PASS")

    print("=" * 68)
    print("ALL V4.12 {} TESTS PASSED".format(scenario.upper()))
    print("=" * 68)
    print()
    print("IMPORTANT:")
    print("CSP-1 and CSP-2 ran as separate Python processes.")
    print("The verifier reconstructed the returned result shares.")
    print("The trusted dealer and local VM filesystem remain trusted.")
    print("MSP structure and public group components remain visible.")
    print("This is not a production-security or formal-proof claim.")


# ==============================================================
# COMMAND LINE
# ==============================================================

def main():
    parser = argparse.ArgumentParser(
        description="AVH-ODBAC V4.12 scalable distributed prototype"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument(
        "--scenario",
        choices=(
            "authorized",
            "unauthorized_receiver",
            "unauthorized_sender",
        ),
        default="authorized",
    )
    prepare_parser.add_argument(
        "--attributes",
        type=int,
        default=DEFAULT_UNIVERSE_SIZE,
        help="Number of attributes in the universe (minimum 2)",
    )
    prepare_parser.add_argument(
        "--triples",
        type=int,
        default=DEFAULT_TRIPLES,
    )

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument(
        "--role",
        choices=("csp1", "csp2"),
        required=True,
    )
    run_parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
    )

    subparsers.add_parser("verify")

    args = parser.parse_args()

    if args.command == "prepare":
        prepare_lab(args.scenario, args.triples, args.attributes)

    elif args.command == "run":
        run_party(args.role, args.port)

    elif args.command == "verify":
        verify_outputs()


if __name__ == "__main__":
    main()

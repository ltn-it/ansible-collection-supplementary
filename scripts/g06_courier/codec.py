"""Ciphertext-only transient courier. No signing-key or provider operation."""

import base64
import hashlib
import json
import os
import re
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TRANSITION_BEFORE = "90e7216b5d085ca4ac6238e44dcdbaa51e847d5f"
BINDING_FIELDS = {
    "transition_before",
    "operation",
    "key_sha256",
    "repository",
    "repository_id",
    "main_sha",
    "workflow_id",
    "run_id",
    "run_attempt",
    "courier_job_id",
    "actor_id",
    "actor",
    "candidate_artifact_id",
    "candidate_digest",
    "candidate_size",
    "controller_sha",
    "issued_at",
    "cutoff_at",
}
ACTORS = {76040632: "litroc", 247824904: "litdeg"}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def decode(raw):
    def unique(items):
        value = {}
        for key, item in items:
            need(key not in value, "duplicate-field")
            value[key] = item
        return value

    need(type(raw) is bytes and len(raw) <= 32768, "courier-bound")
    return json.loads(raw, object_pairs_hook=unique)


def public_key(raw):
    key = serialization.load_pem_public_key(raw)
    need(
        isinstance(key, rsa.RSAPublicKey) and key.key_size == 3072 and key.public_numbers().e == 65537,
        "courier-rsa3072",
    )
    return key


def public_digest(key):
    return hashlib.sha256(
        key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()


def validate(binding, now):
    need(type(binding) is dict and set(binding) == BINDING_FIELDS, "courier-binding-fields")
    for key, length in (
        ("operation", 32),
        ("key_sha256", 64),
        ("main_sha", 40),
        ("candidate_digest", 64),
        ("controller_sha", 40),
    ):
        need(
            type(binding[key]) is str and re.fullmatch("[a-f0-9]{" + str(length) + "}", binding[key]),
            "courier-binding-digest",
        )
    for key in (
        "repository_id",
        "workflow_id",
        "run_id",
        "run_attempt",
        "courier_job_id",
        "actor_id",
        "candidate_artifact_id",
        "candidate_size",
        "issued_at",
        "cutoff_at",
    ):
        need(type(binding[key]) is int and binding[key] > 0, "courier-binding-number")
    need(binding["transition_before"] == TRANSITION_BEFORE, "courier-intended-main-transition")
    need(
        binding["repository"] == "ltn-it/ansible-collection-supplementary"
        and binding["repository_id"] == 1103407173
        and binding["workflow_id"] == 214182490
        and binding["run_attempt"] == 1
        and binding["actor_id"] in ACTORS
        and binding["actor"] == ACTORS[binding["actor_id"]],
        "courier-native-domain",
    )
    need(
        binding["cutoff_at"] - binding["issued_at"] == 900 and binding["issued_at"] <= now <= binding["cutoff_at"],
        "courier-expired-or-future",
    )


def seal(token, binding, pem, now=None):
    now = int(time.time()) if now is None else now
    validate(binding, now)
    need(
        type(token) is str and 20 <= len(token) <= 16384 and all(32 < ord(char) < 127 for char in token),
        "courier-token-shape",
    )
    key = public_key(pem)
    need(public_digest(key) == binding["key_sha256"], "courier-key-binding")
    aad = canonical(binding)
    secret = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    cipher = AESGCM(secret).encrypt(nonce, canonical({"binding": binding, "token": token}), aad)
    wrapped = key.encrypt(secret, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=aad))

    def encode(raw):
        return base64.b64encode(raw).decode("ascii")

    return canonical(
        {
            "schema": 1,
            "binding": binding,
            "wrapped_key": encode(wrapped),
            "nonce": encode(nonce),
            "ciphertext": encode(cipher),
        }
    )


def open_handoff(raw, key, expected, now=None):
    now = int(time.time()) if now is None else now
    validate(expected, now)
    value = decode(raw)
    need(
        type(value) is dict
        and set(value) == {"schema", "binding", "wrapped_key", "nonce", "ciphertext"}
        and type(value["schema"]) is int
        and value["schema"] == 1
        and value["binding"] == expected,
        "courier-exact-expected-binding",
    )
    need(
        isinstance(key, rsa.RSAPrivateKey) and public_digest(key.public_key()) == expected["key_sha256"],
        "courier-private-key-binding",
    )
    aad = canonical(expected)

    def decode64(name):
        return base64.b64decode(value[name], validate=True)

    secret = key.decrypt(
        decode64("wrapped_key"), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=aad)
    )
    nonce = decode64("nonce")
    need(len(nonce) == 12 and len(secret) == 32, "courier-envelope-shape")
    payload = decode(AESGCM(secret).decrypt(nonce, decode64("ciphertext"), aad))
    need(
        type(payload) is dict
        and set(payload) == {"binding", "token"}
        and payload["binding"] == expected
        and type(payload["token"]) is str
        and 20 <= len(payload["token"]) <= 16384
        and all(32 < ord(c) < 127 for c in payload["token"]),
        "courier-payload-binding",
    )
    return payload["token"]

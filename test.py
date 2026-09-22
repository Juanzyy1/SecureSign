from crypto.verifier import verify_signature

resultado = verify_signature(
    "uploads/contrato.txt",
    "signatures/contrato.sig"
)

print("Firma válida:", resultado)
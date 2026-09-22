from flask import Flask, render_template, request, send_file

from crypto.signer import sign_file
from crypto.verifier import verify_signature
from crypto.hash_utils import calculate_sha256

import os
import json

from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
SIGNATURE_FOLDER = "signatures"
METADATA_FOLDER = "metadata"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNATURE_FOLDER, exist_ok=True)
os.makedirs(METADATA_FOLDER, exist_ok=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/download/<filename>")
def download_signature(filename):

    path = os.path.join(
        SIGNATURE_FOLDER,
        filename
    )

    return send_file(
        path,
        as_attachment=True
    )


@app.route("/sign", methods=["POST"])
def sign():

    file = request.files["document"]
    signer = request.form["signer"]

    filepath = os.path.join(
        UPLOAD_FOLDER,
        file.filename
    )

    file.save(filepath)

    signature_path = os.path.join(
        SIGNATURE_FOLDER,
        file.filename + ".sig"
    )

    sign_file(filepath, signature_path)

    file_hash = calculate_sha256(filepath)

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    metadata = {
        "firmante": signer,
        "fecha": timestamp,
        "archivo": file.filename,
        "hash": file_hash
    }

    metadata_path = os.path.join(
        METADATA_FOLDER,
        file.filename + ".json"
    )

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(
            metadata,
            f,
            indent=4,
            ensure_ascii=False
        )

    return render_template(
        "index.html",
        message="✅ Documento firmado correctamente",
        signer=signer,
        file_hash=file_hash,
        timestamp=timestamp,
        signature_file=file.filename + ".sig"
    )


@app.route("/verify", methods=["POST"])
def verify():

    document = request.files["document"]
    signature = request.files["signature"]

    document_path = os.path.join(
        UPLOAD_FOLDER,
        document.filename
    )

    signature_path = os.path.join(
        SIGNATURE_FOLDER,
        signature.filename
    )

    document.save(document_path)
    signature.save(signature_path)

    result = verify_signature(
        document_path,
        signature_path
    )
    current_hash = calculate_sha256(document_path)    
    if result:

        metadata_path = os.path.join(
            METADATA_FOLDER,
            document.filename + ".json"
        )

        signer = None
        timestamp = None
        file_hash = None

        if os.path.exists(metadata_path):

            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)

            signer = metadata.get("firmante")
            timestamp = metadata.get("fecha")
            file_hash = metadata.get("hash")

        return render_template(
            "index.html",
            valid=True,
            signer=signer,
            timestamp=timestamp,
            file_hash=file_hash,
            current_hash=current_hash
        )

    else:

        original_hash = None

        metadata_path = os.path.join(
            METADATA_FOLDER,
            document.filename + ".json"
        )

        if os.path.exists(metadata_path):

            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)

            original_hash = metadata.get("hash")

        return render_template(
            "index.html",
            invalid=True,
            original_hash=original_hash,
            current_hash=current_hash
        )


if __name__ == "__main__":
    app.run(debug=True)
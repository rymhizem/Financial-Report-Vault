import os, io, struct
from flask import (Flask, render_template, request,
                   send_file, flash, redirect, url_for)
from crypto import encrypt_file, decrypt_file, verify_integrity, ALGORITHMS
import audit, lockout

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR   = os.path.join(BASE_DIR, "static")
VAULT_DIR    = os.path.join(BASE_DIR, "vault")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.secret_key = "vault-secret-key-change-in-production"
os.makedirs(VAULT_DIR, exist_ok=True)
audit.init_db()

# ── Bundle helpers ─────────────────────────────────────────────────────────────
def save_to_vault(original_filename, ciphertext, salt, iv, file_hash, algorithm):
    enc_name   = original_filename + ".enc"
    algo_bytes = algorithm.encode("utf-8")
    with open(os.path.join(VAULT_DIR, enc_name), "wb") as f:
        f.write(struct.pack(">H", len(algo_bytes))); f.write(algo_bytes)
        f.write(salt)
        f.write(struct.pack(">H", len(iv)));         f.write(iv)
        f.write(file_hash.encode("utf-8"));          f.write(ciphertext)
    return enc_name

def load_from_vault(enc_filename):
    with open(os.path.join(VAULT_DIR, enc_filename), "rb") as f:
        algo_len   = struct.unpack(">H", f.read(2))[0]
        algorithm  = f.read(algo_len).decode("utf-8")
        salt       = f.read(16)
        iv_len     = struct.unpack(">H", f.read(2))[0]
        iv         = f.read(iv_len)
        file_hash  = f.read(64).decode("utf-8")
        ciphertext = f.read()
    return ciphertext, salt, iv, file_hash, algorithm

def list_vault():
    return sorted(f for f in os.listdir(VAULT_DIR) if f.endswith(".enc"))

def vault_info():
    return [{
        "name":     f,
        "locked":   lockout.is_locked(f),
        "attempts": lockout.get_attempts(f),
        "max":      lockout.MAX_ATTEMPTS,
    } for f in list_vault()]

#── Index ──────────────────────────────────────────────────────────────────────

@app.route("/")

def index():

    return render_template("index.html", vault_files=vault_info(), algorithms=ALGORITHMS)



# ── Encrypt ────────────────────────────────────────────────────────────────────

@app.route("/encrypt", methods=["POST"])

def encrypt():

    uploaded  = request.files.get("file")

    password  = request.form.get("password", "").strip()

    algorithm = request.form.get("algorithm", "AES-256-CBC").strip()



    if not uploaded or not uploaded.filename:

        flash("Please select a file.", "error"); return redirect(url_for("index"))

    if not password:

        flash("Please enter a password.", "error"); return redirect(url_for("index"))

    if algorithm not in ALGORITHMS:

        flash("Invalid algorithm.", "error"); return redirect(url_for("index"))



    data     = uploaded.read()

    result   = encrypt_file(data, password, algorithm)

    enc_name = save_to_vault(uploaded.filename, result["ciphertext"],

                             result["salt"], result["iv"],

                             result["original_hash"], result["algorithm"])

    audit.log("ENCRYPT", filename=enc_name, algorithm=algorithm, status="success",

              details=f"Original: {len(data)}B | Encrypted: {len(result['ciphertext'])}B")

    flash(f"File encrypted successfully using {algorithm}.", "success")

    return render_template("result.html",

        action="File Encrypted Successfully", filename=enc_name,

        file_hash=result["original_hash"], algorithm=algorithm,

        hash_label="Original SHA-256 fingerprint", success=True, error=None)



# ── Decrypt ────────────────────────────────────────────────────────────────────

@app.route("/decrypt", methods=["POST"])

def decrypt():

    enc_filename = request.form.get("enc_file", "").strip()

    password     = request.form.get("password", "").strip()



    if not enc_filename:

        flash("No file selected.", "error"); return redirect(url_for("index"))



    if lockout.is_locked(enc_filename):

        audit.log("DECRYPT", filename=enc_filename, status="blocked",

                  details="Locked after too many failed attempts")

        return render_template("result.html", action="File Locked", success=False,

            error=f"This file is locked after {lockout.MAX_ATTEMPTS} failed attempts. Unlock it from the Audit log.",

            filename=None, file_hash=None, algorithm=None, hash_label=None)



    try:

        ciphertext, salt, iv, stored_hash, algorithm = load_from_vault(enc_filename)

        plaintext = decrypt_file(ciphertext, password, salt, iv, algorithm)

    except (ValueError, KeyError):

        lockout.record_failure(enc_filename)

        remaining = max(lockout.MAX_ATTEMPTS - lockout.get_attempts(enc_filename), 0)

        audit.log("DECRYPT", filename=enc_filename, status="failed",

                  details=f"Wrong password. {remaining} attempt(s) left.")

        return render_template("result.html", action="Decryption Failed", success=False,

            error=f"Wrong password or corrupted file. {remaining} attempt(s) remaining before lockout.",

            filename=None, file_hash=None, algorithm=None, hash_label=None)



    if not verify_integrity(plaintext, stored_hash):

        audit.log("DECRYPT", filename=enc_filename, algorithm=algorithm,

                  status="tampered", details="Hash mismatch")

        return render_template("result.html", action="Tamper Detected", success=False,

            error="SHA-256 hash mismatch — this file has been modified since encryption.",

            filename=None, file_hash=stored_hash, algorithm=algorithm, hash_label="Stored fingerprint")



    lockout.record_success(enc_filename)

    audit.log("DECRYPT", filename=enc_filename, algorithm=algorithm,

              status="success", details="Integrity verified. File delivered.")

    return send_file(io.BytesIO(plaintext), as_attachment=True, download_name=enc_filename[:-4])



# ── Verify ─────────────────────────────────────────────────────────────────────

@app.route("/verify", methods=["POST"])

def verify():

    enc_filename = request.form.get("enc_file", "").strip()

    password     = request.form.get("password", "").strip()



    if not enc_filename:

        flash("No file selected.", "error"); return redirect(url_for("index"))



    if lockout.is_locked(enc_filename):

        audit.log("VERIFY", filename=enc_filename, status="blocked")

        return render_template("result.html", action="File Locked", success=False,

            error=f"This file is locked. Unlock it from the Audit log.",

            filename=None, file_hash=None, algorithm=None, hash_label=None)



    try:

        ciphertext, salt, iv, stored_hash, algorithm = load_from_vault(enc_filename)

        plaintext = decrypt_file(ciphertext, password, salt, iv, algorithm)

    except (ValueError, KeyError):

        lockout.record_failure(enc_filename)

        remaining = max(lockout.MAX_ATTEMPTS - lockout.get_attempts(enc_filename), 0)

        audit.log("VERIFY", filename=enc_filename, status="failed",

                  details=f"Wrong password. {remaining} attempt(s) left.")

        return render_template("result.html", action="Verification Failed", success=False,

            error=f"Wrong password or corrupted file. {remaining} attempt(s) remaining.",

            filename=None, file_hash=None, algorithm=None, hash_label=None)



    intact = verify_integrity(plaintext, stored_hash)

    lockout.record_success(enc_filename)

    audit.log("VERIFY", filename=enc_filename, algorithm=algorithm,

              status="success" if intact else "tampered",

              details="Hash matched" if intact else "Hash mismatch")

    return render_template("result.html",

        action="Integrity Verified — File Is Intact" if intact else "Tamper Detected",

        success=intact, file_hash=stored_hash, algorithm=algorithm,

        hash_label="Stored SHA-256 fingerprint", filename=None,

        error=None if intact else "Hash mismatch — the file has been tampered with.")



# ── Delete ─────────────────────────────────────────────────────────────────────

@app.route("/delete", methods=["POST"])

def delete():

    enc_filename = request.form.get("enc_file", "").strip()

    path = os.path.join(VAULT_DIR, enc_filename)

    if enc_filename and os.path.isfile(path):

        os.remove(path)

        lockout.unlock(enc_filename)

        audit.log("DELETE", filename=enc_filename, status="success")

        flash(f"{enc_filename} removed from vault.", "info")

    else:

        flash("File not found.", "error")

    return redirect(url_for("index"))



# ── Unlock ─────────────────────────────────────────────────────────────────────

@app.route("/unlock", methods=["POST"])

def unlock():

    enc_filename = request.form.get("enc_file", "").strip()

    lockout.unlock(enc_filename)

    audit.log("UNLOCK", filename=enc_filename, status="success", details="Manually unlocked")

    flash(f"{enc_filename} has been unlocked.", "success")

    return redirect(url_for("audit_log"))



# ── Audit log ──────────────────────────────────────────────────────────────────

@app.route("/audit")

def audit_log():

    logs = audit.get_logs()

    return render_template("audit.html", logs=logs)



@app.route("/audit/clear", methods=["POST"])

def audit_clear():

    audit.clear_logs()

    flash("Audit log cleared.", "info")

    return redirect(url_for("audit_log"))



if __name__ == "__main__":

    app.run(debug=True)

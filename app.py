from flask import Flask, render_template, abort, send_from_directory, jsonify
import os
import sys
import subprocess

# Get base project directory
BASE_DIR = os.path.dirname(__file__)
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
PYTHON_PATH = sys.executable

# Initialize Flask app and set template folder
app = Flask(__name__, template_folder="templates")

# Function to open and display Python code in a template page
def _render_code(filename: str, title: str):
    path = os.path.join(TEMPLATES_DIR, filename)
    if not os.path.isfile(path):
        abort(404)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    return render_template("code_view.html", title=title, filename=filename, code=content)

# Home page route
@app.route("/")
def home():
    return render_template("home.html")

# Run encrypt.py script
@app.route("/encrypt")
def encrypt():
    script_path = os.path.join(TEMPLATES_DIR, "encrypt.py")
    try:
        subprocess.Popen([PYTHON_PATH, script_path])
        return jsonify({"success": True, "message": "Encryption tool launched"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# Display decrypt.py script
@app.route("/decrypt")
def decrypt():
    script_path = os.path.join(TEMPLATES_DIR, "decrypt.py")
    try:
        subprocess.Popen([PYTHON_PATH, script_path])
        return jsonify({"success": True, "message": "Decryption tool launched"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# Display check.py script
@app.route("/check")
def check():
    script_path = os.path.join(TEMPLATES_DIR, "check.py")
    try:
        subprocess.Popen([PYTHON_PATH, script_path])
        return jsonify({"success": True, "message": "Check/Monitor tool launched"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# Download script files only
@app.route("/download/<path:filename>")
def download_file(filename: str):
    allowed = {"encrypt.py", "decrypt.py", "check.py"}
    if filename not in allowed:
        abort(404)
    return send_from_directory(TEMPLATES_DIR, filename, as_attachment=True)

# Start Flask server
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

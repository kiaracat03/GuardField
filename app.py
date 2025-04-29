from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)

@app.route("/", methods = ["GET", "POST"])
def index():
    output = None
    if request.method == "POST":
        user_input = request.form["user_input"].strip()

        try:
            # run nessus script with user input and capture output
            result = subprocess.run(["python3", "nessusV2.py", "quick", user_input], capture_output = True, text = True)
            output = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

        except Exception as e:
            output = f"Execution failed: {str(e)}"

    return render_template("index.html", output = output)

@app.route("/about", methods = ["GET", "POST"])
def about_me():
    return render_template("about_me.html")

@app.route("/create", methods = ["GET", "POST"])
def create_scan():
    output = None
    if request.method == "POST":
        user_input = request.form["user_input"].strip()

        try:
            # run nessus script with user input and capture output
            result = subprocess.run(["python3", "nessusV2.py", "create", user_input], capture_output = True, text = True)
            output = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

        except Exception as e:
            output = f"Execution failed: {str(e)}"

    return render_template("create_scan.html", output = output)

@app.route("/vulns", methods = ["GET", "POST"])
def vulns():
    output = None
    if request.method == "POST":
        # user_input = request.form["user_input"].strip()

        try:
            # run last vulnerability function
            result = subprocess.run(["python3", "nessusV2.py", "last"])
            output = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

        except Exception as e:
            output = f"Execution failed: {str(e)}"

    return render_template("vulns.html", output = output)


if __name__ == '__main__':
    app.run(host = "0.0.0.0", port = 5000, debug = True)

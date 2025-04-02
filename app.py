<<<<<<< HEAD
from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)

@app.route("/", methods = ["GET", "POST"])

def index():
    output = None
    scan = None
    if request.method == "POST":
        user_input = request.form["user_input"].strip()

        try:
            # run nessus script with user input and capture output
            scan = subprocess.run(["python3", "nessusV2.py", "quick", user_input])
            # result = subprocess.run(["python3", "nessusV2.py", "quick", user_input], capture_output = True, text = True)
            result = subprocess.run(["python3", "nessusV2.py", "last"], capture_output = True, text = True)

            output = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

        except Exception as e:
            output = f"Execution failed: {str(e)}"

    return render_template("index.html", output = output)

if __name__ == '__main__':
    app.run(host = "0.0.0.0", port = 5000, debug = True)
=======
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/", methods = ["GET", "POST"])

def index():
    output = None
    if request.method == "POST":
        user_input = request.form["user_input"]

        try:
            # run script.sh with user input and capture output
            result = subprocess.run(["bash", "script.sh", user_input], capture_output = True, text = True)
            output = result.stdout 
            
            if result.returncode == 0 else f"Error: {result.stderr}"

        except Exception as e:
            output = f"Execution failed: {str(e)}"

        return render_template("index.html", output = output)
        

if __name__ == '__main__':
    app.run(debug = True, port = 5001)
    # app.run(host = "0.0.0.0", port = 5000, debug = True)
>>>>>>> 64982d46410b735128d7de672f6a62d0f2b36e50

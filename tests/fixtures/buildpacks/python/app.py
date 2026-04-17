import os
from flask import Flask

app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello from rchab buildpacks test\n"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 3000)))

from flask import Flask, request, render_template
import pickle
from ml.generate_pw import password_features
import pandas as pd
app = Flask(__name__)


def validate_password(password):
    clf = pickle.load(open("ml/model.pkl", "rb"))
    features = password_features(password)
    df = pd.DataFrame([features])
    if clf.predict(df)[0] == 1:
        return (True, features)
    else:
        return (False, features)


@app.route('/', methods=["GET", "POST"])
def index():
    if request.method == "POST":
        debug = True if "debug" in request.args else False
        if "password" in request.form:
            password = request.form["password"]
            validate, features = validate_password(password)
            if validate:
                msg = "Confirmed identity. Here is the secret flag: TG20{patterns_not_secured_by_AI}"
            else:
                msg = "The machine beats you!"
        else:
            msg = "Error"
        return render_template("index.html", message=msg, debug=debug, features=features)
    else:
        return render_template('index.html')



if __name__ == '__main__':
    app.run()

from flask import Flask, render_template, url_for, request, redirect
from blockchain.blockchain import BlockchainDB

app = Flask(__name__)

db = BlockchainDB("app")


@app.route("/")
def index():
    return redirect("/home")


@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/blockchain", methods=["GET", "POST"])
def blockchain():
    if request.method == "POST":
        print(request, request.get_data())
        if request.json:
            print(request.json)
            content = request.get_json()
            print(content)
            if content["action"] == "create_user":
                print("create user")
                return db.add_user(
                    content["name"],
                    int(content["privilege_level"]),
                    content["type"],
                )
            if content["action"] == "delete_user":
                print("delete user")
                return db.delete_user(
                    int(content["public_key"]),
                    int(content["private_key"]),
                )
            if content["action"] == "diagnose":
                print("diagnose")
                return db.add_diagnosis(
                    int(content["doc_public_key"]),
                    int(content["doc_private_key"]),
                    int(content["public_key"]),
                    content["diagnosis"],
                )
            if content["action"] == "read":
                print("read")
                return db.read_records(int(content["public_key"]))
        else:
            print(request.form.to_dict())
            print(request.form)
            if request.form.get("action") == "create_user":
                print("create user")
                return db.add_user(
                    request.form.get("name"),
                    int(request.form.get("privilege_level")),
                    request.form.get("type"),
                )
            if request.form.get("action") == "delete_user":
                print("delete user")
                return db.delete_user(
                    int(request.form.get("public_key")),
                    int(request.form.get("private_key")),
                )
            if request.form.get("action") == "diagnose":
                print("diagnose")
                return db.add_diagnosis(
                    int(request.form.get("doc_public_key")),
                    int(request.form.get("doc_private_key")),
                    int(request.form.get("public_key")),
                    request.form.get("diagnosis"),
                )
            if request.form.get("action") == "read":
                print("read")
                return db.read_records(int(request.form.get("public_key")))
    return render_template("blockchain.html")


if __name__ == "__main__":
    app.run(debug=True)

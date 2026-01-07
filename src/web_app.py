from flask import Flask, render_template, request, redirect, url_for

from auth import login_user, logout_user, is_logged_in, is_admin
from firewall import check_packet
from metrics import stats, blocked_ips
from packet import Packet
from rules import firewall_rules, add_rule, delete_rule, get_rule, update_rule

app = Flask(__name__)
app.secret_key = "supersecretkey"


# -------------------- LOGIN --------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if login_user(username, password):
            return redirect(url_for("index"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


# -------------------- FIREWALL SIMULATOR --------------------

@app.route("/", methods=["GET", "POST"])
def index():
    if not is_logged_in():
        return redirect(url_for("login"))

    decision = None

    if request.method == "POST":
        packet = Packet(
            src_ip=request.form["src_ip"],
            dst_ip=request.form["dst_ip"],
            src_port=0,
            dst_port=int(request.form["dst_port"]),
            protocol=request.form["protocol"]
        )

        decision = check_packet(packet)

    return render_template("index.html", decision=decision)


# -------------------- DASHBOARD --------------------

@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        allow=stats["ALLOW"],
        deny=stats["DENY"],
        blocked_ips=blocked_ips
    )


# -------------------- MANAGE RULES (ADMIN ONLY) --------------------

@app.route("/rules", methods=["GET", "POST"])
def manage_rules():
    if not is_logged_in():
        return redirect(url_for("login"))

    if not is_admin():
        return "Access Denied: Admins only", 403

    if request.method == "POST":
        rule = {
            "id": len(firewall_rules) + 1,
            "priority": int(request.form["priority"]),
            "action": request.form["action"],
            "protocol": request.form.get("protocol") or None,
            "dst_port": int(request.form["dst_port"]) if request.form.get("dst_port") else None
        }
        add_rule(rule)

    return render_template("rules.html", rules=firewall_rules)


# -------------------- DELETE RULE (ADMIN ONLY) --------------------

@app.route("/rules/delete/<int:rule_id>", methods=["POST"])
def delete_firewall_rule(rule_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    if not is_admin():
        return "Access Denied: Admins only", 403

    delete_rule(rule_id)
    return redirect(url_for("manage_rules"))


# -------------------- EDIT RULE (ADMIN ONLY) --------------------

@app.route("/rules/edit/<int:rule_id>", methods=["GET", "POST"])
def edit_firewall_rule(rule_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    if not is_admin():
        return "Access Denied: Admins only", 403

    rule = get_rule(rule_id)
    if not rule:
        return redirect(url_for("manage_rules"))

    if request.method == "POST":
        updated = {
            "priority": int(request.form["priority"]),
            "action": request.form["action"],
            "protocol": request.form.get("protocol") or None,
            "dst_port": int(request.form["dst_port"]) if request.form.get("dst_port") else None
        }
        update_rule(rule_id, updated)
        return redirect(url_for("manage_rules"))

    return render_template("edit_rule.html", rule=rule)


# -------------------- START APP --------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )

from flask import Flask, render_template, request, redirect, url_for
from metrics import get_metrics
from auth import login_user, logout_user, is_logged_in, is_admin
from firewall import check_packet
from packet import Packet
from rules import firewall_rules, add_rule, delete_rule, get_rule, update_rule, save_rules
from audit import log_audit
from alerts import load_alerts

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
    metrics = get_metrics()
    alerts = load_alerts()

    # Prepare rule hit data
    rule_labels = []
    rule_hits = []

    for rule in firewall_rules:
        label = f"Rule {rule['id']} ({rule['action']})"
        rule_labels.append(label)
        rule_hits.append(rule.get("hit_count", 0))

    return render_template(
        "dashboard.html",
        allow=metrics["allow"],
        deny=metrics["deny"],
        blocked_ips=metrics["blocked_ips"],
        rule_labels=rule_labels,
        rule_hits=rule_hits
    )


# -------------------- MANAGE RULES (ADMIN ONLY) --------------------

@app.route("/rules", methods=["GET", "POST"])
def manage_rules():
    if not is_logged_in():
        return redirect(url_for("login"))

    if not is_admin():
        return "Access Denied: Admins only", 403
#------------------------ Add Rule -----------------------------------
    if request.method == "POST":
        rule = {
            "id": len(firewall_rules) + 1,
            "priority": int(request.form["priority"]),
            "action": request.form["action"],
            "protocol": request.form.get("protocol") or None,
            "dst_port": int(request.form["dst_port"]) if request.form.get("dst_port") else None
        }
        log_audit(session["user"], "ADD_RULE", rule["id"], after=rule)
        add_rule(rule)

    return render_template("rules.html", rules=firewall_rules)


# -------------------- DELETE RULE (ADMIN ONLY) --------------------

@app.route("/rules/delete/<int:rule_id>", methods=["POST"])
def delete_rule(rule_id):
    global firewall_rules

    firewall_rules = [r for r in firewall_rules if r["id"] != rule_id]
    save_rules(firewall_rules)
    before = rule.copy()
    log_audit(session["user"], "DELETE_RULE", rule_id, before=before)
    return redirect("/rules")



# -------------------- EDIT RULE (ADMIN ONLY) --------------------

@app.route("/rules/edit/<int:rule_id>", methods=["GET"])
def edit_rule(rule_id):
    rule = next((r for r in firewall_rules if r["id"] == rule_id), None)

    if not rule:
        return "Rule not found", 404

    return render_template("edit_rule.html", rule=rule)

@app.route("/rules/edit/<int:rule_id>", methods=["POST"])
def update_rule(rule_id):
    for rule in firewall_rules:
        if rule["id"] == rule_id:
            rule["priority"] = int(request.form["priority"])
            rule["action"] = request.form["action"]
            rule["protocol"] = request.form.get("protocol") or None
            rule["dst_port"] = (
                int(request.form["dst_port"])
                if request.form.get("dst_port")
                else None
            ) # modify rule
            before = rule.copy()
            log_audit(session["user"], "EDIT_RULE", rule_id, before=before, after=rule)
            save_rules(firewall_rules)
            break

    return redirect("/rules")


# -------------------- START APP --------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )

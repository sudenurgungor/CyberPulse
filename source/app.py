from flask import Flask, render_template, request, redirect, session, flash, jsonify, Response
from db import (
    get_recent_attacks,
    get_blocked_ips,
    get_ip_list,
    add_ip_to_list,
    delete_ip_from_list,
    get_db_connection,
    delete_blocked_ip,
    save_blocked_ip_to_db,
    save_to_db,
    get_attack_stats,
    get_filtered_attack_logs
)
import os
import ipaddress
import json
import csv
import io
from datetime import datetime


app = Flask(__name__)
app.secret_key = "supersecretkey"


login_attempts = {}

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_TIME_WINDOW = 60


def login_required():
    return "user" in session


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def block_ip_iptables(ip):
    check_command = f"iptables -C INPUT -s {ip} -j DROP > /dev/null 2>&1"
    add_command = f"iptables -A INPUT -s {ip} -j DROP"

    rule_exists = os.system(check_command) == 0

    if not rule_exists:
        os.system(add_command)
        print(f"[FIREWALL] {ip} blocked")
    else:
        print(f"[FIREWALL] {ip} already blocked")


def unblock_ip_iptables(ip):
    while True:
        result = os.system(
            f"sudo iptables -D INPUT -s {ip} -j DROP > /dev/null 2>&1"
        )

        if result != 0:
            break

    while True:
        result = os.system(
            f"sudo iptables -D FORWARD -s {ip} -j DROP > /dev/null 2>&1"
        )

        if result != 0:
            break

    print(f"[FIREWALL] {ip} unblocked")


def save_blocked_ip_to_file(ip):
    file_path = "logs/blocked_ips.txt"

    if not os.path.exists("logs"):
        os.makedirs("logs")

    existing_ips = []

    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            existing_ips = [line.strip() for line in file.readlines()]

    if ip not in existing_ips:
        with open(file_path, "a") as file:
            file.write(ip + "\n")


def remove_ip_from_blocked_file(ip):
    file_path = "logs/blocked_ips.txt"

    if not os.path.exists(file_path):
        return

    with open(file_path, "r") as file:
        lines = file.readlines()

    with open(file_path, "w") as file:
        for line in lines:
            if line.strip() != ip:
                file.write(line)


def clear_blocked_ip_file():
    if not os.path.exists("logs"):
        os.makedirs("logs")

    open("logs/blocked_ips.txt", "w").close()


def get_all_blocked_ips_for_reset():
    ip_set = set()

    try:
        db_ips = get_blocked_ips(1000)

        for item in db_ips:
            if len(item) > 1:
                ip_set.add(item[1])
    except Exception as error:
        print("DB blocked IP read error:", error)

    try:
        with open("logs/blocked_ips.txt", "r") as file:
            for line in file:
                ip = line.strip()

                if ip:
                    ip_set.add(ip)
    except FileNotFoundError:
        pass

    return list(ip_set)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user_ip = request.remote_addr
        current_time = datetime.now().timestamp()

        if user_ip not in login_attempts:
            login_attempts[user_ip] = []

        login_attempts[user_ip] = [
            t for t in login_attempts[user_ip]
            if current_time - t <= BRUTE_FORCE_TIME_WINDOW
        ]

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=%s AND password=%s",
            (username, password)
        )

        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user:
            login_attempts[user_ip] = []
            session["user"] = username
            return redirect("/")

        login_attempts[user_ip].append(current_time)

        if len(login_attempts[user_ip]) >= BRUTE_FORCE_THRESHOLD:
            print(f"[BRUTE FORCE] Detected from {user_ip}")

            block_ip_iptables(user_ip)
            save_blocked_ip_to_file(user_ip)
            save_blocked_ip_to_db(user_ip, "Brute force attack")

            save_to_db(
                "Brute Force",
                user_ip,
                "192.168.56.104",
                None,
                5000,
                "HTTP",
                "High",
                "Too many failed login attempts",
                "blocked",
                "blocked"
            )

            return render_template(
                "login.html",
                error="Too many attempts. IP blocked."
            )

        return render_template(
            "login.html",
            error="Access denied. Invalid credentials."
        )

    return render_template("login.html")


@app.route("/")
def dashboard():
    if not login_required():
        return redirect("/login")

    attacks = get_recent_attacks(10)
    blocked_ips = get_blocked_ips(10)
    stats = get_attack_stats()

    return render_template(
        "dashboard.html",
        attacks=attacks,
        blocked_ips=blocked_ips,
        stats=stats
    )


@app.route("/api/dashboard-data")
def dashboard_data():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 401

    attacks = get_recent_attacks(10)
    blocked_ips = get_blocked_ips(10)
    stats = get_attack_stats()

    attack_list = []

    for attack in attacks:
        attack_list.append({
            "id": attack[0],
            "attack_type": attack[1],
            "source_ip": attack[2],
            "target_ip": attack[3],
            "protocol": attack[4],
            "severity": attack[5],
            "status": attack[6],
            "action": attack[7],
            "detected_at": attack[8].strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify({
        "stats": stats,
        "blocked_count": len(blocked_ips),
        "attacks": attack_list
    })


@app.route("/reset-blocks", methods=["GET", "POST"])
def reset_blocks():
    if not login_required():
        return redirect("/login")

    blocked_ip_list = get_all_blocked_ips_for_reset()

    for ip in blocked_ip_list:
        if is_valid_ip(ip):
            unblock_ip_iptables(ip)
            delete_blocked_ip(ip)

    clear_blocked_ip_file()

    flash("All blocked IP rules have been reset successfully.", "success")

    if request.method == "POST":
        return jsonify({
            "message": "All blocked IP rules have been reset successfully.",
            "reset_count": len(blocked_ip_list)
        })

    return redirect("/blocked-ips")


@app.route("/ip-lists", methods=["GET", "POST"])
def ip_lists():
    if not login_required():
        return redirect("/login")

    if request.method == "POST":
        ip_address = request.form["ip_address"]
        list_type = request.form["list_type"]
        reason = request.form["reason"]

        if not is_valid_ip(ip_address):
            flash("Invalid IP address.", "error")
            return redirect("/ip-lists")

        if list_type not in ["whitelist", "blacklist"]:
            flash("Invalid list type.", "error")
            return redirect("/ip-lists")

        added = add_ip_to_list(ip_address, list_type, reason)

        if added:
            flash("IP address added successfully.", "success")
        else:
            flash("IP already exists.", "error")

        return redirect("/ip-lists")

    whitelist = get_ip_list("whitelist")
    blacklist = get_ip_list("blacklist")

    return render_template(
        "ip_lists.html",
        whitelist=whitelist,
        blacklist=blacklist
    )


@app.route("/ip-lists/delete/<int:ip_id>")
def delete_ip(ip_id):
    if not login_required():
        return redirect("/login")

    delete_ip_from_list(ip_id)
    flash("IP address removed from list.", "success")

    return redirect("/ip-lists")


@app.route("/blocked-ips")
def blocked_ips_page():
    if not login_required():
        return redirect("/login")

    ips = get_blocked_ips(50)

    return render_template("blocked_ips.html", ips=ips)


@app.route("/unblock/<ip>")
def unblock_ip(ip):
    if not login_required():
        return redirect("/login")

    if not is_valid_ip(ip):
        flash("Invalid IP address.", "error")
        return redirect("/blocked-ips")

    unblock_ip_iptables(ip)

    delete_blocked_ip(ip)
    remove_ip_from_blocked_file(ip)

    flash("IP unblocked successfully.", "success")

    return redirect("/blocked-ips")


@app.route("/logs")
def logs_page():
    if not login_required():
        return redirect("/login")

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    source_ip = request.args.get("source_ip")
    attack_type = request.args.get("attack_type")
    severity = request.args.get("severity")

    logs = get_filtered_attack_logs(
        start_date=start_date,
        end_date=end_date,
        source_ip=source_ip,
        attack_type=attack_type,
        severity=severity
    )

    return render_template(
        "logs.html",
        logs=logs,
        start_date=start_date or "",
        end_date=end_date or "",
        source_ip=source_ip or "",
        attack_type=attack_type or "",
        severity=severity or ""
    )


@app.route("/logs/download")
def download_logs():
    if not login_required():
        return redirect("/login")

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    source_ip = request.args.get("source_ip")
    attack_type = request.args.get("attack_type")
    severity = request.args.get("severity")

    logs = get_filtered_attack_logs(
        start_date=start_date,
        end_date=end_date,
        source_ip=source_ip,
        attack_type=attack_type,
        severity=severity
    )

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Attack Type",
        "Source IP",
        "Target IP",
        "Source Port",
        "Target Port",
        "Protocol",
        "Severity",
        "Description",
        "Status",
        "Action",
        "Detected At"
    ])

    for log in logs:
        writer.writerow([
            log[0],
            log[1],
            log[2],
            log[3],
            log[4],
            log[5],
            log[6],
            log[7],
            log[8],
            log[9],
            log[10],
            log[11]
        ])

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=attack_logs.csv"
        }
    )


@app.route("/test")
def test():
    return "Test page"


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if not login_required():
        return redirect("/login")

    if request.method == "POST":
        rules = {
            "sql_block_threshold": max(1, int(request.form.get("sql_threshold"))),
            "xss_block_threshold": max(1, int(request.form.get("xss_threshold"))),
            "high_traffic_threshold": max(1, int(request.form.get("traffic_threshold"))),
            "port_scan_threshold": max(1, int(request.form.get("port_threshold"))),
            "sql_block_enabled": "sql_enabled" in request.form,
            "xss_block_enabled": "xss_enabled" in request.form,
            "high_traffic_block_enabled": "traffic_enabled" in request.form,
            "port_scan_block_enabled": "port_enabled" in request.form
        }

        with open("rules_config.json", "w") as file:
            json.dump(rules, file, indent=4)

        flash("Settings updated successfully.", "success")
        return redirect("/settings")

    with open("rules_config.json", "r") as file:
        rules = json.load(file)

    return render_template("settings.html", rules=rules)


@app.route("/reset-rules")
def reset_rules():
    if not login_required():
        return redirect("/login")

    default_rules = {
        "sql_block_threshold": 3,
        "xss_block_threshold": 3,
        "high_traffic_threshold": 40,
        "port_scan_threshold": 5,
        "sql_block_enabled": True,
        "xss_block_enabled": True,
        "high_traffic_block_enabled": True,
        "port_scan_block_enabled": True
    }

    with open("rules_config.json", "w") as file:
        json.dump(default_rules, file, indent=4)

    flash("Rule settings reset to default values.", "success")
    return redirect("/settings")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
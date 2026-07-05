import psycopg2
from config import DB_HOST, DB_NAME, DB_USER, DB_PASSWORD


def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )


def save_to_db(attack_type, source_ip, target_ip, source_port, target_port, protocol, severity, description, status, action):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO attacks
            (attack_type, source_ip, target_ip, source_port, target_port, protocol, severity, description, status, action_taken)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (attack_type, source_ip, target_ip, source_port, target_port, protocol, severity, description, status, action))

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print("DB ERROR:", e)


def save_blocked_ip_to_db(ip, reason):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO blocked_ips (ip_address, block_reason)
            VALUES (%s, %s)
            ON CONFLICT (ip_address) DO NOTHING
        """, (ip, reason))

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print("DB BLOCK ERROR:", e)


def get_recent_attacks(limit=10):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT id, attack_type, source_ip, target_ip, protocol, severity, status, action_taken, detected_at
            FROM attacks
            ORDER BY detected_at DESC
            LIMIT %s
        """, (limit,))

        rows = cur.fetchall()
        cur.close()
        conn.close()

        return rows

    except Exception as e:
        print("DB READ ERROR:", e)
        return []


def get_filtered_attack_logs(start_date=None, end_date=None, source_ip=None, attack_type=None, severity=None):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        query = """
            SELECT id, attack_type, source_ip, target_ip, source_port, target_port,
                   protocol, severity, description, status, action_taken, detected_at
            FROM attacks
            WHERE 1=1
        """

        params = []

        if start_date:
            query += " AND detected_at::date >= %s"
            params.append(start_date)

        if end_date:
            query += " AND detected_at::date <= %s"
            params.append(end_date)

        if source_ip:
            query += " AND source_ip = %s"
            params.append(source_ip)

        if attack_type:
            query += " AND LOWER(attack_type) LIKE LOWER(%s)"
            params.append(f"%{attack_type}%")

        if severity:
            query += " AND LOWER(severity) = LOWER(%s)"
            params.append(severity)

        query += " ORDER BY detected_at DESC"

        cur.execute(query, tuple(params))

        rows = cur.fetchall()
        cur.close()
        conn.close()

        return rows

    except Exception as e:
        print("DB FILTERED LOG ERROR:", e)
        return []


def get_attack_stats():
    stats = {
        "total_attacks": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "port_scan_count": 0,
        "high_traffic_count": 0,
        "sql_count": 0,
        "xss_count": 0,
        "brute_count": 0
    }

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM attacks")
        stats["total_attacks"] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM attacks WHERE LOWER(severity)='high'")
        stats["high_count"] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM attacks WHERE LOWER(severity)='medium'")
        stats["medium_count"] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM attacks WHERE LOWER(severity)='low'")
        stats["low_count"] = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM attacks
            WHERE LOWER(REPLACE(attack_type, '_', ' ')) = 'port scan'
        """)
        stats["port_scan_count"] = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM attacks
            WHERE LOWER(REPLACE(attack_type, '_', ' ')) = 'high traffic'
        """)
        stats["high_traffic_count"] = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM attacks
            WHERE LOWER(attack_type) LIKE '%sql%'
        """)
        stats["sql_count"] = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM attacks
            WHERE LOWER(attack_type) LIKE '%xss%'
        """)
        stats["xss_count"] = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM attacks
            WHERE LOWER(attack_type) = 'brute force'
        """)
        stats["brute_count"] = cur.fetchone()[0]

        cur.close()
        conn.close()

    except Exception as e:
        print("DB STATS ERROR:", e)

    return stats


def get_blocked_ips(limit=10):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT id, ip_address, block_reason, blocked_at
            FROM blocked_ips
            ORDER BY blocked_at DESC
            LIMIT %s
        """, (limit,))

        rows = cur.fetchall()
        cur.close()
        conn.close()

        return rows

    except Exception as e:
        print("DB READ ERROR:", e)
        return []


def get_ip_list(list_type):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, ip_address, list_type, reason, created_at
            FROM ip_lists
            WHERE list_type=%s
            ORDER BY created_at DESC
        """, (list_type,))

        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return rows

    except Exception as e:
        print("DB IP LIST READ ERROR:", e)
        return []


def add_ip_to_list(ip_address, list_type, reason):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO ip_lists (ip_address, list_type, reason)
            VALUES (%s, %s, %s)
            ON CONFLICT (ip_address, list_type) DO NOTHING
        """, (ip_address, list_type, reason))

        added = cursor.rowcount > 0

        conn.commit()
        cursor.close()
        conn.close()

        return added

    except Exception as e:
        print("DB IP LIST ADD ERROR:", e)
        return False


def delete_ip_from_list(ip_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM ip_lists WHERE id=%s",
            (ip_id,)
        )

        conn.commit()
        cursor.close()
        conn.close()

    except Exception as e:
        print("DB IP LIST DELETE ERROR:", e)


def delete_blocked_ip(ip_address):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM blocked_ips WHERE ip_address=%s",
            (ip_address,)
        )

        conn.commit()
        cursor.close()
        conn.close()

    except Exception as e:
        print("DB BLOCK DELETE ERROR:", e)
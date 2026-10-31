import re
import pandas as pd
import numpy as np

def run_rule_based_detection(df):
    alerts = []
    
    # Sort chronologically to properly evaluate sequencing (LS002)
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    # LS001: Brute-force Login Attempts
    # Identify source IPs with more than 5 failed logins within 5 mins
    for ip, group in df.groupby('ip'):
        failures = group[group['auth_result'] == 'failed']
        if not failures.empty:
            rolling_failures = failures.set_index('timestamp').rolling('300s')['log_id'].count()
            max_fails = rolling_failures.max() if not rolling_failures.empty else 0
            if max_fails >= 5:
                alerts.append({
                    "alert_id": f"ALT-LS001-{ip}",
                    "rule_id": "LS001",
                    "scenario": "brute_force",
                    "title": "Brute-force login activity detected",
                    "severity": "High",
                    "source_ip": ip,
                    "username": group.get('username', pd.Series(['-'])).iloc[0],
                    "event_count": int(max_fails),
                    "time_window": "5 minutes",
                    "detection_source": "rule_based",
                    "evidence": [
                        "Repeated failed login events",
                        f"Source IP address matched: {ip}",
                        "Events occurred within the configured 5-minute time window"
                    ],
                    "status": "needs_review",
                    "recommendation": "Review authentication activity and apply appropriate account protection."
                })
                
    # LS002: Failed logins followed by successful login
    for ip, group in df.groupby('ip'):
        group_sorted = group.sort_values('timestamp')
        for i in range(len(group_sorted)):
            row = group_sorted.iloc[i]
            if row['auth_result'] == 'success':
                # Check past failures for the same IP within the preceding 5 minutes
                past_window = group_sorted[(group_sorted['timestamp'] < row['timestamp']) & 
                                           (group_sorted['timestamp'] >= row['timestamp'] - pd.Timedelta('300s'))]
                fails_count = (past_window['auth_result'] == 'failed').sum()
                if fails_count >= 3:
                    alerts.append({
                        "alert_id": f"ALT-LS002-{ip}",
                        "rule_id": "LS002",
                        "scenario": "failed_login_followed_by_success",
                        "title": "Failed login attempts followed by successful login",
                        "severity": "High",
                        "source_ip": ip,
                        "username": row.get('username', 'user1'),
                        "failed_attempts": int(fails_count),
                        "final_result": "Successful login",
                        "detection_source": "rule_based",
                        "evidence": [
                            f"Successful login occurred for account after {fails_count} failures within 5 minutes."
                        ],
                        "status": "needs_review"
                    })
                    break # Avoid duplicate alert counts for single sequence

    # LS003-4XX: Repeated HTTP 4xx Client Errors
    for ip, group in df.groupby('ip'):
        errors_4xx = group[(group['status'] >= 400) & (group['status'] < 500)]
        if not errors_4xx.empty:
            rolling_4xx = errors_4xx.set_index('timestamp').rolling('300s')['log_id'].count()
            max_4xx = rolling_4xx.max() if not rolling_4xx.empty else 0
            if max_4xx >= 4:
                alerts.append({
                    "alert_id": f"ALT-LS003-4XX-{ip}",
                    "rule_id": "LS003-4XX",
                    "scenario": "repeated_4xx",
                    "title": "Repeated HTTP 4xx client errors detected",
                    "severity": "Medium",
                    "source_ip": ip,
                    "endpoint": errors_4xx['endpoint'].iloc[0],
                    "error_count": int(max_4xx),
                    "detection_source": "rule_based",
                    "evidence": [f"Detected {max_4xx} client errors within 5 minutes from {ip}."],
                    "status": "needs_review"
                })

    # LS003-5XX: Repeated HTTP 5xx Server Errors
    for ip, group in df.groupby('ip'):
        errors_5xx = group[(group['status'] >= 500) & (group['status'] < 600)]
        if not errors_5xx.empty:
            rolling_5xx = errors_5xx.set_index('timestamp').rolling('300s')['log_id'].count()
            max_5xx = rolling_5xx.max() if not rolling_5xx.empty else 0
            if max_5xx >= 4:
                alerts.append({
                    "alert_id": f"ALT-LS003-5XX-{ip}",
                    "rule_id": "LS003-5XX",
                    "scenario": "repeated_5xx",
                    "title": "Repeated HTTP 5xx server errors detected",
                    "severity": "High",
                    "source_ip": ip,
                    "endpoint": errors_5xx['endpoint'].iloc[0],
                    "error_count": int(max_5xx),
                    "detection_source": "rule_based",
                    "evidence": [f"Detected {max_5xx} server/database exceptions within 5 minutes."],
                    "status": "needs_review"
                })

    # LS004: SQL injection-like patterns
    sql_regex = re.compile(r"(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|--|OR\s+1=1)", re.IGNORECASE)
    for idx, row in df.iterrows():
        path_str = str(row.get('path', ''))
        if sql_regex.search(path_str) or sql_regex.search(str(row.get('endpoint', ''))):
            alerts.append({
                "alert_id": f"ALT-LS004-{row['log_id']}",
                "rule_id": "LS004",
                "scenario": "sql_injection_pattern",
                "title": "SQL injection-like request pattern detected",
                "severity": "High",
                "source_ip": row['ip'],
                "endpoint": row['endpoint'],
                "pattern": "UNION SELECT",
                "description": "Request contains a pattern commonly associated with SQL injection attempts.",
                "detection_source": "rule_based",
                "evidence": [
                    f"SQL keyword sequence discovered in requested path: {path_str}"
                ],
                "status": "needs_review",
                "recommendation": "Review the request and verify that database queries use parameterized statements."
            })
            
    return alerts

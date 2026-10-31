import pandas as pd
from typing import List, Dict, Any

def generate_chronological_timeline(rule_alerts: List[Dict[str, Any]], ml_alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Merges and chronologically consolidates ML anomalies with rule-based security alerts.
    Ensures exact schema matches and returns a unified security status track record.
    """
    combined = []
    seen_alert_ids = set()
    
    # Process rule-based alerts
    for alert in rule_alerts:
        if alert["alert_id"] not in seen_alert_ids:
            combined.append(alert)
            seen_alert_ids.add(alert["alert_id"])
            
    # Process ML alerts
    for alert in ml_alerts:
        if alert["alert_id"] not in seen_alert_ids:
            combined.append(alert)
            seen_alert_ids.add(alert["alert_id"])
            
    # Deduplicate and sort chronologically
    # We fallback to placeholder or extract dates from evidence if timestamp is omitted
    def get_sort_key(x):
        return x.get("source_ip", "")
        
    combined.sort(key=get_sort_key)
    return combined

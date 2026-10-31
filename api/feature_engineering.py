import pandas as pd
import numpy as np

def compute_log_features(df):
    """
    Computes sliding-window features from a raw DataFrame of logs.
    Compatible with both training batches and real-time inference payloads.
    """
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    # Temporary feature calculation helpers
    df['is_auth_fail'] = (df['auth_result'] == 'failed').astype(int)
    df['is_auth_success'] = (df['auth_result'] == 'success').astype(int)
    df['is_4xx'] = ((df['status'] >= 400) & (df['status'] < 500)).astype(int)
    df['is_5xx'] = ((df['status'] >= 500) & (df['status'] < 600)).astype(int)
    df['hour'] = df['timestamp'].dt.hour
    
    features_list = []
    for ip, group in df.groupby('ip'):
        sub_df = group.set_index('timestamp').sort_index()
        
        # 300-second rolling sliding window aggregations
        rolling_count = sub_df['log_id'].rolling('300s').count()
        rolling_auth_fail = sub_df['is_auth_fail'].rolling('300s').sum()
        rolling_auth_success = sub_df['is_auth_success'].rolling('300s').sum()
        rolling_4xx = sub_df['is_4xx'].rolling('300s').sum()
        rolling_5xx = sub_df['is_5xx'].rolling('300s').sum()
        rolling_bytes = sub_df['bytes_sent'].rolling('300s').mean()
        rolling_req_size = sub_df['request_size_bytes'].rolling('300s').mean()
        rolling_resp_time = sub_df['response_time_ms'].rolling('300s').mean()
        rolling_resp_time_max = sub_df['response_time_ms'].rolling('300s').max()
        
        temp_features = pd.DataFrame({
            'log_id': sub_df['log_id'],
            'total_requests': rolling_count,
            'requests_per_minute': rolling_count / 5.0,
            'failed_login_count': rolling_auth_fail,
            'successful_login_count': rolling_auth_success,
            'auth_failure_ratio': np.where(rolling_count > 0, rolling_auth_fail / rolling_count, 0.0),
            'http_4xx_count': rolling_4xx,
            'http_5xx_count': rolling_5xx,
            'avg_response_time': rolling_resp_time,
            'max_response_time': rolling_resp_time_max,
            'avg_bytes_sent': rolling_bytes,
            'avg_request_size': rolling_req_size,
            'hour_sin': np.sin(2 * np.pi * sub_df['hour'] / 24.0),
            'hour_cos': np.cos(2 * np.pi * sub_df['hour'] / 24.0),
            'status_error_ratio': np.where(rolling_count > 0, (rolling_4xx + rolling_5xx) / rolling_count, 0.0)
        })
        features_list.append(temp_features)
        
    if len(features_list) > 0:
        feature_df = pd.concat(features_list).reset_index(drop=True)
    else:
        feature_df = pd.DataFrame(columns=['log_id'])
        
    return feature_df

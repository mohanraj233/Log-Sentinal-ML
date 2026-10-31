from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import pandas as pd
import json
import io
from typing import List

from schemas import SingleLogPayload, ScoreResponse, HealthResponse, AlertDetails
from model_loader import ModelLoader
from feature_engineering import compute_log_features
from detection_rules import run_rule_based_detection
from timeline import generate_chronological_timeline

app = FastAPI(
    title="VibeProof LogSentinel AI Server",
    description="FastAPI cybersecurity threat analysis engine using hybrid ML and heuristic detection.",
    version="1.0.0"
)

@app.on_event("startup")
def startup_event():
    # Eagerly load models on start
    try:
        ModelLoader.load_model()
        ModelLoader.load_metadata()
        print("LogSentinel model assets initialized successfully.")
    except Exception as e:
        print(f"Warning: Model loading failed during startup: {e}")

@app.get("/health", response_model=HealthResponse)
def health_check():
    try:
        metadata = ModelLoader.load_metadata()
        return {
            "status": "healthy",
            "model_loaded": ModelLoader._model is not None,
            "model_version": metadata.get("model_version", "1.0.0"),
            "unsupervised_threshold": metadata.get("threshold", -0.5)
        }
    except Exception as e:
        return {
            "status": "degraded",
            "model_loaded": False,
            "model_version": "unknown",
            "unsupervised_threshold": 0.0
        }

@app.post("/score", response_model=ScoreResponse)
def score_log(payload: SingleLogPayload):
    # Reconstruct the log history and target log into a DataFrame
    logs = [payload.current_log.dict()]
    for hist_log in payload.historical_window:
        logs.append(hist_log.dict())
        
    df = pd.DataFrame(logs)
    
    # 1. Run Rule-based Heuristic Engine
    rule_alerts = run_rule_based_detection(df)
    triggered_rules = list(set([alert["rule_id"] for alert in rule_alerts]))
    
    # 2. Extract ML features & Score Anomaly
    ml_alerts = []
    anomaly_score = 0.0
    is_suspicious_ml = False
    
    try:
        model = ModelLoader.load_model()
        meta = ModelLoader.load_metadata()
        features_df = compute_log_features(df)
        
        # Pull out current record's engineered row
        target_features = features_df[features_df['log_id'] == payload.current_log.log_id]
        if not target_features.empty:
            feature_cols = meta.get("feature_names", [])
            X = target_features[feature_cols]
            pred = model.predict(X)[0]
            score = float(model.score_samples(X)[0])
            anomaly_score = score
            
            if pred == -1:
                is_suspicious_ml = True
                ml_alerts.append({
                    "alert_id": f"ALT-ML-{payload.current_log.log_id}",
                    "rule_id": "ML-ANOMALY",
                    "scenario": "unsupervised_anomaly",
                    "title": "Machine Learning Anomaly Detected",
                    "severity": "High",
                    "source_ip": payload.current_log.ip,
                    "username": payload.current_log.username,
                    "detection_source": "ml_based",
                    "evidence": [
                        f"Log score of {score:.4f} is below isolation threshold.",
                        f"Requests frequency, byte size, or context deviates from benign profile."
                    ],
                    "status": "needs_review",
                    "recommendation": "Audit source traffic for potential scraping, command injections, or automated probing."
                })
    except Exception as e:
        # Gracefully handle ML processing error and rely on deterministic heuristics
        print(f"ML Scoring exception: {e}")
        
    # Combine security timelines
    all_alerts = generate_chronological_timeline(rule_alerts, ml_alerts)
    is_suspicious = len(all_alerts) > 0 or is_suspicious_ml
    
    return {
        "is_suspicious": is_suspicious,
        "anomaly_score": anomaly_score,
        "triggered_rules": triggered_rules,
        "alerts": all_alerts
    }

@app.post("/analyze-batch")
def analyze_batch(file: UploadFile = File(...)):
    try:
        contents = file.file.read()
        df = pd.read_csv(io.BytesIO(contents))
        
        # Evaluate entire batch via unified engine
        rule_alerts = run_rule_based_detection(df)
        
        ml_alerts = []
        try:
            model = ModelLoader.load_model()
            meta = ModelLoader.load_metadata()
            features_df = compute_log_features(df)
            
            feature_cols = meta.get("feature_names", [])
            X = features_df[feature_cols]
            preds = model.predict(X)
            scores = model.score_samples(X)
            
            for i, pred in enumerate(preds):
                if pred == -1:
                    log_row = df.iloc[i]
                    ml_alerts.append({
                        "alert_id": f"ALT-ML-{log_row['log_id']}",
                        "rule_id": "ML-ANOMALY",
                        "scenario": "unsupervised_anomaly",
                        "title": "Unsupervised isolation forest outlier",
                        "severity": "Medium",
                        "source_ip": log_row['ip'],
                        "username": str(log_row.get('username', '-')),
                        "detection_source": "ml_based",
                        "evidence": [f"Low Isolation Forest density score: {scores[i]:.4f}"],
                        "status": "needs_review"
                    })
        except Exception as e:
            print(f"Batch ML execution omitted: {e}")
            
        unified_timeline = generate_chronological_timeline(rule_alerts, ml_alerts)
        
        return {
            "filename": file.filename,
            "total_processed_logs": len(df),
            "total_alerts_found": len(unified_timeline),
            "timeline_alerts": unified_timeline
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Batch execution failure: {str(e)}")

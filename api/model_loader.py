import os
import json
import joblib

MODEL_PATH = "LogSentinel_ML/models/isolation_forest.joblib"
METADATA_PATH = "LogSentinel_ML/models/model_metadata.json"

class ModelLoader:
    _model = None
    _metadata = None

    @classmethod
    def load_model(cls):
        if cls._model is None:
            if os.path.exists(MODEL_PATH):
                cls._model = joblib.load(MODEL_PATH)
            else:
                raise FileNotFoundError(f"Isolation Forest model file not found at {MODEL_PATH}")
        return cls._model

    @classmethod
    def load_metadata(cls):
        if cls._metadata is None:
            if os.path.exists(METADATA_PATH):
                with open(METADATA_PATH, "r") as f:
                    cls._metadata = json.load(f)
            else:
                cls._metadata = {
                    "model_name": "IsolationForest",
                    "model_version": "1.0.0",
                    "feature_names": [],
                    "threshold": 0.0
                }
        return cls._metadata

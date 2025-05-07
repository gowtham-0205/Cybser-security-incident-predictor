# ml_models.py - Machine Learning Models
import numpy as np
import pandas as pd
import pickle
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix
import xgboost as xgb
from xgboost import XGBClassifier

# In a production environment, these would be trained models
# Here, we're providing simplified implementations for demonstration

# Paths to saved model artifacts
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
XGBOOST_MODEL_PATH = os.path.join(MODEL_DIR, 'xgboost_model.pkl')
TFIDF_VECTORIZER_PATH = os.path.join(MODEL_DIR, 'tfidf_vectorizer.pkl')
LABEL_ENCODERS_PATH = os.path.join(MODEL_DIR, 'label_encoders.pkl')

def risk_analyzer(features):
    """
    Analyzes various features to determine risk level
    
    Args:
        features (dict): Dictionary containing security features
        
    Returns:
        dict: Risk assessment results
    """
    # In practice, you would load a trained model
    # For demo purposes, we'll use a simple rule-based system
    
    risk_score = 0
    
    # SSL features
    if not features.get('has_ssl', False):
        risk_score += 30
    elif not features.get('cert_valid', False):
        risk_score += 20
    elif not features.get('hsts', False):
        risk_score += 10
    
    # Port features
    open_ports = features.get('open_ports', [])
    risky_ports = [21, 23, 3306, 8080]
    for port in risky_ports:
        if port in open_ports:
            risk_score += 10
    
    # Domain age
    domain_age = features.get('domain_age', 0)  # in years
    if domain_age < 1:
        risk_score += 15
    elif domain_age < 3:
        risk_score += 5
    
    # IP reputation
    if features.get('blacklisted', False):
        risk_score += 40
    elif features.get('suspicious', False):
        risk_score += 20
    
    # Cap at 100
    risk_score = min(risk_score, 100)
    
    # Determine risk level
    if risk_score >= 70:
        risk_level = 'High'
    elif risk_score >= 40:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level
    }

def anomaly_detector(traffic_data):
    """
    Detects anomalies in website traffic patterns
    
    Args:
        traffic_data (list): List of traffic metrics
        
    Returns:
        list: Anomaly scores for each data point
    """
    # In practice, you would load a trained model
    # For demo purposes, we'll use a simple isolation forest
    
    # Format data for the model
    X = np.array(traffic_data).reshape(-1, 1)
    
    # Initialize and fit the model
    clf = IsolationForest(n_estimators=100, contamination=0.1)
    clf.fit(X)
    
    # Get anomaly scores (-1 for anomalies, 1 for normal)
    scores = clf.predict(X)
    
    # Convert to anomaly confidence (0-1 where 1 is highly anomalous)
    anomaly_scores = [0 if score == 1 else 1 for score in scores]
    
    return anomaly_scores

def load_cybersecurity_models():
    """
    Loads the trained XGBoost model and preprocessors for cybersecurity detection
    
    Returns:
        tuple: (xgboost_model, tfidf_vectorizer, label_encoders)
    """
    try:
        # Load XGBoost model
        model = joblib.load(XGBOOST_MODEL_PATH)
        
        # Load TF-IDF vectorizer for User Agent processing
        tfidf_vectorizer = joblib.load(TFIDF_VECTORIZER_PATH)
        
        # Load label encoders for categorical variables
        label_encoders = joblib.load(LABEL_ENCODERS_PATH)
        
        return model, tfidf_vectorizer, label_encoders
    except Exception as e:
        print(f"Error loading models: {str(e)}")
        return None, None, None

def save_cybersecurity_models(model, tfidf_vectorizer, label_encoders):
    """
    Saves the trained XGBoost model and preprocessors
    
    Args:
        model: Trained XGBoost model
        tfidf_vectorizer: Fitted TF-IDF vectorizer
        label_encoders: Dictionary of fitted label encoders
    """
    # Create model directory if it doesn't exist
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    # Save the model and preprocessors
    joblib.dump(model, XGBOOST_MODEL_PATH)
    joblib.dump(tfidf_vectorizer, TFIDF_VECTORIZER_PATH)
    joblib.dump(label_encoders, LABEL_ENCODERS_PATH)
    
    print(f"Models saved to {MODEL_DIR}")

def preprocess_cybersecurity_data(data, tfidf_vectorizer, label_encoders, training=False):
    """
    Preprocesses cybersecurity data for the XGBoost model
    
    Args:
        data (pd.DataFrame): Raw cybersecurity data
        tfidf_vectorizer: TF-IDF vectorizer for User Agent
        label_encoders: Dictionary of label encoders for categorical columns
        training (bool): Whether this is for training or prediction
        
    Returns:
        scipy.sparse.csr_matrix: Processed feature matrix
    """
    # Make a copy to avoid modifying the original
    data_copy = data.copy()
    
    # Drop unhelpful or high-cardinality fields if they exist
    cols_to_drop = ['Event ID', 'Timestamp', 'Source IP', 'Destination IP']
    data_copy = data_copy.drop(columns=[col for col in cols_to_drop if col in data_copy.columns])
    
    # Process User Agent with TF-IDF if it exists
    user_agent_tfidf = None
    if 'User Agent' in data_copy.columns:
        if training:
            user_agent_tfidf = tfidf_vectorizer.fit_transform(data_copy['User Agent'])
        else:
            user_agent_tfidf = tfidf_vectorizer.transform(data_copy['User Agent'])
        data_copy = data_copy.drop(columns=['User Agent'])
    
    # Encode categorical variables
    categorical_cols = ['Attack Type', 'Threat Intelligence', 'Response Action', 'Attack Severity']
    for col in categorical_cols:
        if col in data_copy.columns:
            if training:
                le = LabelEncoder()
                data_copy[col] = le.fit_transform(data_copy[col])
                label_encoders[col] = le
            else:
                if col in label_encoders:
                    # Handle unseen labels
                    data_copy[col] = data_copy[col].apply(
                        lambda x: -1 if x not in label_encoders[col].classes_ else label_encoders[col].transform([x])[0]
                    )
    
    # Ensure all remaining features are numeric
    if 'Data Exfiltrated' in data_copy.columns:
        target = data_copy['Data Exfiltrated'].astype(int)
        data_copy = data_copy.drop(columns=['Data Exfiltrated'])
    else:
        target = None
    
    # Convert to numeric and handle non-numeric values
    for col in data_copy.columns:
        data_copy[col] = pd.to_numeric(data_copy[col], errors='coerce').fillna(0)
    
    # Convert to sparse matrix
    X_dense_sparse = csr_matrix(data_copy.values)
    
    # Combine with TF-IDF features if they exist
    if user_agent_tfidf is not None:
        X = hstack([X_dense_sparse, user_agent_tfidf])
    else:
        X = X_dense_sparse
    
    if training:
        return X, target
    else:
        return X

def train_cybersecurity_model(data):
    """
    Trains the XGBoost model on cybersecurity data
    
    Args:
        data (pd.DataFrame): Training data
        
    Returns:
        tuple: (trained_model, tfidf_vectorizer, label_encoders)
    """
    # Initialize preprocessors
    tfidf_vectorizer = TfidfVectorizer(max_features=100)
    label_encoders = {}
    
    # Preprocess data
    X, y = preprocess_cybersecurity_data(data, tfidf_vectorizer, label_encoders, training=True)
    
    # Train XGBoost model
    model = XGBClassifier(use_label_encoder=False, eval_metric='logloss')
    model.fit(X, y)
    
    # Save models
    save_cybersecurity_models(model, tfidf_vectorizer, label_encoders)
    
    return model, tfidf_vectorizer, label_encoders

def predict_data_exfiltration(data):
    """
    Predicts data exfiltration likelihood using the trained XGBoost model
    
    Args:
        data (pd.DataFrame or dict): Security event data
        
    Returns:
        dict: Prediction results including exfiltration probability
    """
    # Convert dict to DataFrame if needed
    if isinstance(data, dict):
        data = pd.DataFrame([data])
    
    # Load models
    model, tfidf_vectorizer, label_encoders = load_cybersecurity_models()
    
    if model is None:
        return {
            'error': 'Model not found. Please train the model first.',
            'exfiltration_detected': False,
            'probability': 0.0
        }
    
    # Preprocess data
    X = preprocess_cybersecurity_data(data, tfidf_vectorizer, label_encoders, training=False)
    
    # Make prediction
    y_pred_proba = model.predict_proba(X)[:, 1]
    y_pred = model.predict(X)
    
    # Determine confidence level
    if y_pred_proba[0] > 0.8:
        confidence = 'Very High'
    elif y_pred_proba[0] > 0.6:
        confidence = 'High'
    elif y_pred_proba[0] > 0.4:
        confidence = 'Moderate'
    elif y_pred_proba[0] > 0.2:
        confidence = 'Low'
    else:
        confidence = 'Very Low'
    
    return {
        'exfiltration_detected': bool(y_pred[0]),
        'probability': float(y_pred_proba[0]),
        'confidence': confidence
    }
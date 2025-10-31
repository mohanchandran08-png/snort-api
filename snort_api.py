from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import mysql.connector
import json
import re
from typing import Optional

app = FastAPI()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Configuration
DB_CONFIG = {
    "host": "45.127.5.229",
    "user": "Libr_lmangskie",
    "password": "StrongPassword123!",
    "database": "Libr_auth_system"
}


# Data Models
class SnortAlert(BaseModel):
    attack_type: str
    source_ip: str
    destination_ip: str
    rule_priority: int
    summary: str
    detection_mode: str = "simulated"

# Database Connection
def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

# SQL Injection Detection Function
def detect_sql_injection(data: str) -> tuple[bool, Optional[str]]:
    """
    Detect SQL injection patterns in input data
    Returns: (is_injection, matched_pattern)
    """
    sql_patterns = [
        (r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b)", "UNION/SELECT detected"),
        (r"(\bINSERT\b.*\bINTO\b|\bDROP\b.*\bTABLE\b)", "INSERT/DROP detected"),
        (r"(--|\/\*|\*\/)", "SQL comment detected"),
        (r"(\'\s*\)|\'\s*OR|\'\s*AND)", "SQL escape sequence detected"),
        (r"\bUNION\s+SELECT\b", "UNION SELECT detected"),
        (r"(\bOR\b\s*1\s*=\s*1|\bAND\b\s*1\s*=\s*1)", "Boolean-based SQLi detected"),
        (r"(SLEEP\s*\(|BENCHMARK\s*\()", "Time-based SQLi detected"),
        (r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP)", "Stacked query detected"),
        (r"xp_|sp_", "Stored procedure detected"),
        (r"CAST\s*\(|CONVERT\s*\(", "Type conversion detected"),
    ]
    
    for pattern, description in sql_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True, description
    
    return False, None

# Store Alert in Database
def store_alert(alert_data: dict) -> bool:
    """Store alert in database"""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    try:
        query = """
        INSERT INTO snort_alerts 
        (attack_type, source_ip, destination_ip, rule_priority, summary, alert_time, detection_mode)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            alert_data.get('attack_type'),
            alert_data.get('source_ip'),
            alert_data.get('destination_ip'),
            alert_data.get('rule_priority', 3),
            alert_data.get('summary'),
            datetime.now(),
            alert_data.get('detection_mode', 'simulated')
        )
        cursor.execute(query, values)
        conn.commit()
        return True
    except Exception as e:
        print(f"Error storing alert: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

# ==================== ENDPOINTS ====================

@app.post("/api/snort-alert")
async def receive_snort_alert(alert: SnortAlert):
    """
    Endpoint to receive simulated alerts
    """
    alert_dict = alert.dict()
    alert_dict['detection_mode'] = 'simulated'
    
    if store_alert(alert_dict):
        return {
            "status": "success",
            "message": "Simulated alert received",
            "detection_mode": "simulated"
        }
    return {"status": "error", "message": "Failed to store alert"}

@app.post("/api/detect-injection")
async def detect_injection(data: dict):
    """
    Endpoint for real SQL injection detection
    Input: {"input": "data to test", "source_ip": "IP", "destination_ip": "IP"}
    """
    test_input = data.get('input', '')
    source_ip = data.get('source_ip', '0.0.0.0')
    destination_ip = data.get('destination_ip', '45.127.5.229')
    
    is_injection, pattern_desc = detect_sql_injection(test_input)
    
    if is_injection:
        # Create alert for real detection
        alert = {
            'attack_type': 'SQL INJECTION',
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'rule_priority': 8,
            'summary': f'Detected: {pattern_desc} - Input: {test_input[:100]}',
            'detection_mode': 'real'
        }
        store_alert(alert)
        
        return {
            "status": "attack_detected",
            "attack_type": "SQL INJECTION",
            "severity": "HIGH",
            "pattern": pattern_desc,
            "input": test_input[:100]
        }
    
    return {
        "status": "safe",
        "message": "No SQL injection detected"
    }

@app.get("/api/alerts")
async def get_alerts(mode: Optional[str] = None, limit: int = 100):
    """
    Retrieve alerts from database
    Optional filter by mode: 'simulated', 'real'
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    cursor = conn.cursor(dictionary=True)
    try:
        if mode and mode in ['simulated', 'real']:
            query = "SELECT * FROM snort_alerts WHERE detection_mode = %s ORDER BY alert_time DESC LIMIT %s"
            cursor.execute(query, (mode, limit))
        else:
            query = "SELECT * FROM snort_alerts ORDER BY alert_time DESC LIMIT %s"
            cursor.execute(query, (limit,))
        
        alerts = cursor.fetchall()
        return {
            "status": "success",
            "total": len(alerts),
            "alerts": alerts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()

@app.get("/api/stats")
async def get_stats():
    """Get alert statistics"""
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    cursor = conn.cursor(dictionary=True)
    try:
        # Stats by detection mode
        cursor.execute("SELECT detection_mode, COUNT(*) as count FROM snort_alerts GROUP BY detection_mode")
        mode_stats = cursor.fetchall()
        
        # Stats by attack type
        cursor.execute("SELECT attack_type, COUNT(*) as count FROM snort_alerts GROUP BY attack_type ORDER BY count DESC")
        type_stats = cursor.fetchall()
        
        # High priority alerts
        cursor.execute("SELECT COUNT(*) as count FROM snort_alerts WHERE rule_priority >= 7")
        high_priority = cursor.fetchone()
        
        return {
            "by_detection_mode": mode_stats,
            "by_attack_type": type_stats,
            "high_priority_alerts": high_priority['count'] if high_priority else 0
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    conn = get_db_connection()
    db_status = "connected" if conn else "disconnected"
    if conn:
        conn.close()
    
    return {
        "status": "healthy",
        "database": db_status,
        "api_version": "2.0",
        "features": ["simulated_alerts", "real_sql_injection_detection"]
    }

@app.get("/")
async def root():
    return {
        "message": "LibraTrack API - Dual-Mode Detection",
        "version": "2.0",
        "endpoints": {
            "simulated": "/api/snort-alert (POST)",
            "real_detection": "/api/detect-injection (POST)",
            "get_alerts": "/api/alerts (GET)",
            "statistics": "/api/stats (GET)",
            "health": "/api/health (GET)"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

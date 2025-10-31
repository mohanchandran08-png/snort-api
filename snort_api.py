from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import mysql.connector
from mysql.connector import Error
from datetime import datetime
import os
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Snort Alert Integration API",
    description="Real-time network intrusion alert system for LibraTrack",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'database': os.getenv('DB_NAME', 'Libr_auth_system'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'port': int(os.getenv('DB_PORT', 3306))
}

# Pydantic Models
class SnortAlert(BaseModel):
    attack_type: str
    source_ip: str
    destination_ip: Optional[str] = None
    rule_priority: str
    summary: str
    alert_time: Optional[str] = None

class SnortAlertResponse(BaseModel):
    id: int
    attack_type: str
    source_ip: str
    destination_ip: Optional[str]
    rule_priority: str
    summary: str
    alert_time: str

# Database Functions
def get_db_connection():
    """Create and return a MySQL database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        logger.error(f"Database connection error: {e}")
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")

def create_snort_alerts_table():
    """Create snort_alerts table if it doesn't exist"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        create_table_query = """
        CREATE TABLE IF NOT EXISTS snort_alerts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            attack_type VARCHAR(255) NOT NULL,
            source_ip VARCHAR(45) NOT NULL,
            destination_ip VARCHAR(45),
            rule_priority VARCHAR(50) NOT NULL,
            summary TEXT NOT NULL,
            alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_alert_time (alert_time),
            INDEX idx_priority (rule_priority),
            INDEX idx_source_ip (source_ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """
        
        cursor.execute(create_table_query)
        connection.commit()
        logger.info("snort_alerts table created successfully")
        
    except Error as e:
        logger.error(f"Error creating table: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Routes
@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "Snort Alert Integration API",
        "status": "online",
        "version": "1.0.0"
    }

@app.get("/health")
async def health():
    """Health check with database connection test"""
    try:
        connection = get_db_connection()
        if connection.is_connected():
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            connection.close()
            return {
                "status": "healthy",
                "database": "connected"
            }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")

@app.post("/api/snort-alert")
async def receive_snort_alert(alert: SnortAlert):
    """
    Receive a Snort alert and store it in the database
    
    Example payload:
    {
        "attack_type": "SQL Injection Attempt",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "rule_priority": "High",
        "summary": "Potential SQL injection detected in GET parameter"
    }
    """
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        # Use provided alert_time or current time
        alert_time = alert.alert_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        insert_query = """
        INSERT INTO snort_alerts 
        (attack_type, source_ip, destination_ip, rule_priority, summary, alert_time)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        values = (
            alert.attack_type,
            alert.source_ip,
            alert.destination_ip,
            alert.rule_priority,
            alert.summary,
            alert_time
        )
        
        cursor.execute(insert_query, values)
        connection.commit()
        alert_id = cursor.lastrowid
        
        logger.info(f"Alert stored successfully with ID: {alert_id}")
        
        return {
            "success": True,
            "message": "Alert stored successfully",
            "alert_id": alert_id
        }
        
    except Error as e:
        logger.error(f"Error storing alert: {e}")
        raise HTTPException(status_code=500, detail=f"Error storing alert: {str(e)}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/api/alerts")
async def get_alerts_simple():
    """
    Get all recent Snort alerts - SIMPLE VERSION (NO PARAMETERS)
    Returns last 20 alerts ordered by most recent first
    """
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        select_query = "SELECT id, attack_type, source_ip, destination_ip, rule_priority, summary, DATE_FORMAT(alert_time, '%Y-%m-%d %H:%i:%s') as alert_time FROM snort_alerts ORDER BY alert_time DESC LIMIT 20"
        
        cursor.execute(select_query)
        alerts = cursor.fetchall()
        
        return {
            "success": True,
            "total": len(alerts),
            "alerts": alerts
        }
        
    except Error as e:
        logger.error(f"Error retrieving alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/api/get-snort-alerts")
async def get_snort_alerts(limit: int = 5, offset: int = 0):
    """
    Get recent Snort alerts from the database
    
    Query Parameters:
    - limit: Number of alerts to return (default: 5)
    - offset: Number of alerts to skip (default: 0)
    """
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Limit the maximum number of alerts to prevent abuse
        limit = min(limit, 100)
        
        select_query = """
        SELECT 
            id,
            attack_type,
            source_ip,
            destination_ip,
            rule_priority,
            summary,
            DATE_FORMAT(alert_time, '%Y-%m-%d %H:%i:%s') as alert_time
        FROM snort_alerts
        ORDER BY alert_time DESC
        LIMIT {limit} OFFSET {offset}
        """
        
        cursor.execute(select_query)
        alerts = cursor.fetchall()
        
        # Get total count
        cursor.execute("SELECT COUNT(*) as total FROM snort_alerts")
        total = cursor.fetchone()['total']
        
        return {
            "success": True,
            "total": total,
            "alerts": alerts,
            "limit": limit,
            "offset": offset
        }
        
    except Error as e:
        logger.error(f"Error retrieving alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving alerts: {str(e)}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/api/get-snort-alerts-stats")
async def get_snort_alerts_stats():
    """Get statistics about stored alerts"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Get priority counts
        cursor.execute("""
        SELECT rule_priority, COUNT(*) as count
        FROM snort_alerts
        GROUP BY rule_priority
        """)
        priority_stats = cursor.fetchall()
        
        # Get total alerts
        cursor.execute("SELECT COUNT(*) as total FROM snort_alerts")
        total = cursor.fetchone()['total']
        
        # Get alerts in last hour
        cursor.execute("""
        SELECT COUNT(*) as count
        FROM snort_alerts
        WHERE alert_time >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        """)
        last_hour = cursor.fetchone()['count']
        
        return {
            "success": True,
            "total_alerts": total,
            "alerts_last_hour": last_hour,
            "by_priority": priority_stats
        }
        
    except Error as e:
        logger.error(f"Error retrieving stats: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving stats: {str(e)}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.delete("/api/snort-alerts/{alert_id}")
async def delete_snort_alert(alert_id: int):
    """Delete a specific Snort alert by ID"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        delete_query = "DELETE FROM snort_alerts WHERE id = %s"
        cursor.execute(delete_query, (alert_id,))
        connection.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return {
            "success": True,
            "message": f"Alert {alert_id} deleted successfully"
        }
        
    except Error as e:
        logger.error(f"Error deleting alert: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting alert: {str(e)}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Startup event
@app.on_event("startup")
async def startup_event():
    """Create tables on startup"""
    logger.info("Starting up Snort Alert API...")
    create_snort_alerts_table()
    logger.info("Startup complete!")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Snort Alert API...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

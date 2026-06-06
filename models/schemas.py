"""
Pydantic schemas for request/response models.
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class TransactionType(str, Enum):
    TRANSFER = "transfer"
    PAYMENT = "payment"
    WITHDRAWAL = "withdrawal"
    DEPOSIT = "deposit"


class Transaction(BaseModel):
    transaction_id: str
    sender_id: str
    receiver_id: str
    amount: float = Field(..., gt=0)
    timestamp: datetime
    transaction_type: TransactionType
    currency: str = "USD"
    sender_ip: Optional[str] = None
    receiver_ip: Optional[str] = None
    sender_device_id: Optional[str] = None
    receiver_device_id: Optional[str] = None
    description: Optional[str] = None


class FraudIndicator(BaseModel):
    indicator_name: str
    indicator_score: float  # 0.0 - 1.0
    details: str


class FraudCircle(BaseModel):
    circle_id: str
    members: List[str]
    circle_size: int
    total_amount: float
    transaction_count: int
    risk_score: float


class FraudScoreResponse(BaseModel):
    transaction_id: str
    overall_fraud_score: float  # 0.0 - 1.0
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    is_fraud_circle_member: bool
    fraud_circles: List[FraudCircle]
    indicators: List[FraudIndicator]
    sender_risk_score: float
    receiver_risk_score: float
    recommendation: str


class GraphStatsResponse(BaseModel):
    total_nodes: int
    total_edges: int
    total_transactions: int
    detected_circles: int
    high_risk_accounts: int
    avg_fraud_score: float
    top_fraud_circles: List[FraudCircle]
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from typing import List
import logging

from models.graph_engine import FraudGraphEngine
from models.fraud_scorer import FraudScorer
from models.schemas import (
    Transaction, FraudScoreResponse, GraphStatsResponse,
    FraudCircle
)

logger = logging.getLogger(__name__)

graph_engine : FraudGraphEngine = None
fraud_scorer: FraudScorer = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """ Engine lifespan """
    global graph_engine,fraud_scorer
    logger.info("initializing Fraud engine ...")
    graph_engine= FraudGraphEngine()
    fraud_scorer = FraudScorer()
    logger.info("Fraud engine initialized")
    yield
    logger.info("Fraud engine shutdown")

app = FastAPI(
    title="Graph-Based Fraud Detection API",
    description=(
        "Real-time fraud detection system using graph analysis "
        "to identify fraud circles and score transactions."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/v1/transactions", response_model=FraudScoreResponse)

async def score_transaction(transaction: Transaction):
    """
    Submit a transaction for fraud scoring.

    The transaction is added to the graph and analyzed for:
    - Fraud circle membership
    - Account risk scores
    - Transaction anomalies
    - Velocity patterns
    - Network structure anomalies

    Returns a comprehensive fraud score with detailed indicators.
    """
    try:
        result = fraud_scorer.score_transaction(transaction)
        return result
    except Exception as e:
        logger.error(f"error scoring transaction: {e}",exc_info= True)
        raise HTTPException(status_code=500, detail= f"error scoring transaction {str(e)}")



@app.post("/api/v1/transactions/batch", response_model=List[FraudScoreResponse])
async def score_batch_transactions(transactions: List[Transaction]):
    """Submit a batch of transactions for fraud scoring."""
    try:
        results = []
        for transaction in transactions:
            results.append(await score_transaction(transaction))
        return results
    except Exception as e:
        logger.error(f"error scoring transactions: {e}",exc_info= True)
        raise HTTPException(status_code=500, detail= f"error scoring batch {str(e)}")

@app.get("/api/v1/graph/stats", response_model=GraphStatsResponse)
async def get_graph_stats():
    """Get current graph statistics and top fraud circles."""
    try:
        stats = graph_engine.get_graph_stats()
        return GraphStatsResponse(
            total_nodes=stats["total_nodes"],
            total_edges=stats["total_edges"],
            total_transactions=stats["total_transactions"],
            detected_circles=stats["detected_circles"],
            high_risk_accounts=stats["high_risk_accounts"],
            avg_fraud_score=stats["avg_fraud_score"],
            top_fraud_circles=[
                FraudCircle(**{
                    k: c[k] for k in
                    ["circle_id", "members", "circle_size",
                     "total_amount", "transaction_count", "risk_score"]
                })
                for c in stats["top_fraud_circles"]
            ],
        )
    except Exception as e:
        logger.error(f"Error getting stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/accounts/{account_id}/risk")
async def get_account_risk(account_id: str):
    """Get risk score and fraud circle membership for an account."""
    risk_score = graph_engine.get_account_risk_score(account_id)
    circles = graph_engine.get_fraud_circles_for_account(account_id)

    return {
        "account_id": account_id,
        "risk_score": risk_score,
        "risk_level": (
            "CRITICAL" if risk_score >= 0.75 else
            "HIGH" if risk_score >= 0.50 else
            "MEDIUM" if risk_score >= 0.25 else
            "LOW"
        ),
        "fraud_circles": [
            FraudCircle(**{
                k: c[k] for k in
                ["circle_id", "members", "circle_size",
                 "total_amount", "transaction_count", "risk_score"]
            })
            for c in circles
        ],
        "is_circle_member": account_id in graph_engine.circle_members,
    }


@app.get("/api/v1/circles", response_model=List[FraudCircle])
async def get_fraud_circles():
    """Get all detected fraud circles."""
    return [
        FraudCircle(**{
            k: c[k] for k in
            ["circle_id", "members", "circle_size",
             "total_amount", "transaction_count", "risk_score"]
        })
        for c in graph_engine.fraud_circles
    ]

@app.post("/api/v1/circles/detect")
async def trigger_circle_detection():
    """Manually trigger fraud circle detection."""
    circles = graph_engine.detect_fraud_circles()
    return {
        "status": "completed",
        "circles_detected": len(circles),
        "circles": [
            FraudCircle(**{
                k: c[k] for k in
                ["circle_id", "members", "circle_size",
                 "total_amount", "transaction_count", "risk_score"]
            })
            for c in circles
        ],
    }

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "graph_nodes": graph_engine.graph.number_of_nodes() if graph_engine else 0,
        "graph_edges": graph_engine.graph.number_of_edges() if graph_engine else 0,
        "transactions_processed": len(graph_engine.transactions) if graph_engine else 0,
    }
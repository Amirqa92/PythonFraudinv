"""
Fraud scoring module that combines graph-based signals with
transaction-level features to produce a comprehensive fraud score.
"""
import networkx as nx
from typing import List
from models.graph_engine import FraudGraphEngine
from models.schemas import (
    Transaction, FraudScoreResponse, FraudIndicator,
    FraudCircle
)
import logging

logger = logging.getLogger(__name__)


class FraudScorer:
    """
    Combines multiple fraud detection signals to produce
    a comprehensive fraud score for each transaction.
    """

    def __init__(self, graph_engine: FraudGraphEngine):
        self.graph_engine = graph_engine
        # Weights for different signal categories
        self.weights = {
            "circle_membership": 0.30,
            "account_risk": 0.25,
            "transaction_anomaly": 0.25,
            "velocity": 0.10,
            "network_structure": 0.10,
        }

    def score_transaction(self, transaction: Transaction) -> FraudScoreResponse:
        """Score a single transaction for fraud risk."""
        tx_dict = transaction.model_dump()
        if isinstance(tx_dict.get("timestamp"), str):
            from datetime import datetime
            tx_dict["timestamp"] = datetime.fromisoformat(tx_dict["timestamp"])

        # Add transaction to graph
        self.graph_engine.add_transaction(tx_dict)

        # Collect all fraud indicators
        indicators: List[FraudIndicator] = []

        # 1. Circle membership analysis
        circle_score, circle_indicators = self._analyze_circle_membership(
            transaction.sender_id, transaction.receiver_id
        )
        indicators.extend(circle_indicators)

        # 2. Account risk analysis
        sender_risk = self.graph_engine.get_account_risk_score(transaction.sender_id)
        receiver_risk = self.graph_engine.get_account_risk_score(transaction.receiver_id)
        account_score = max(sender_risk, receiver_risk)

        if sender_risk > 0.5:
            indicators.append(FraudIndicator(
                indicator_name="HIGH_RISK_SENDER",
                indicator_score=sender_risk,
                details=f"Sender {transaction.sender_id} has risk score {sender_risk:.3f}"
            ))
        if receiver_risk > 0.5:
            indicators.append(FraudIndicator(
                indicator_name="HIGH_RISK_RECEIVER",
                indicator_score=receiver_risk,
                details=f"Receiver {transaction.receiver_id} has risk score {receiver_risk:.3f}"
            ))

        # 3. Transaction-level anomaly analysis
        tx_anomaly_score, tx_indicators = self._analyze_transaction_anomalies(transaction)
        indicators.extend(tx_indicators)

        # 4. Velocity analysis
        velocity_score, vel_indicators = self._analyze_velocity(
            transaction.sender_id, transaction.timestamp
        )
        indicators.extend(vel_indicators)

        # 5. Network structure analysis
        network_score, net_indicators = self._analyze_network_structure(
            transaction.sender_id, transaction.receiver_id
        )
        indicators.extend(net_indicators)

        # Calculate weighted overall score
        overall_score = (
            self.weights["circle_membership"] * circle_score +
            self.weights["account_risk"] * account_score +
            self.weights["transaction_anomaly"] * tx_anomaly_score +
            self.weights["velocity"] * velocity_score +
            self.weights["network_structure"] * network_score
        )
        overall_score = round(min(overall_score, 1.0), 4)

        # Determine risk level
        risk_level = self._get_risk_level(overall_score)

        # Get fraud circles for involved accounts
        fraud_circles = []
        seen_circle_ids = set()
        for account_id in [transaction.sender_id, transaction.receiver_id]:
            for circle in self.graph_engine.get_fraud_circles_for_account(account_id):
                if circle["circle_id"] not in seen_circle_ids:
                    seen_circle_ids.add(circle["circle_id"])
                    fraud_circles.append(FraudCircle(**{
                        k: circle[k] for k in
                        ["circle_id", "members", "circle_size",
                         "total_amount", "transaction_count", "risk_score"]
                    }))

        is_circle_member = (
            transaction.sender_id in self.graph_engine.circle_members or
            transaction.receiver_id in self.graph_engine.circle_members
        )

        recommendation = self._get_recommendation(overall_score, risk_level, indicators)

        return FraudScoreResponse(
            transaction_id=transaction.transaction_id,
            overall_fraud_score=overall_score,
            risk_level=risk_level,
            is_fraud_circle_member=is_circle_member,
            fraud_circles=fraud_circles,
            indicators=indicators,
            sender_risk_score=sender_risk,
            receiver_risk_score=receiver_risk,
            recommendation=recommendation,
        )

    def _analyze_circle_membership(
        self, sender_id: str, receiver_id: str
    ) -> tuple[float, List[FraudIndicator]]:
        """Analyze if sender or receiver are part of fraud circles."""
        indicators = []
        max_score = 0.0

        for account_id, role in [(sender_id, "sender"), (receiver_id, "receiver")]:
            circles = self.graph_engine.get_fraud_circles_for_account(account_id)
            if circles:
                best_circle = max(circles, key=lambda c: c["risk_score"])
                max_score = max(max_score, best_circle["risk_score"])
                indicators.append(FraudIndicator(
                    indicator_name=f"FRAUD_CIRCLE_{role.upper()}",
                    indicator_score=best_circle["risk_score"],
                    details=(
                        f"{role.capitalize()} {account_id} is part of "
                        f"{len(circles)} fraud circle(s). "
                        f"Highest risk circle: {best_circle['circle_id']} "
                        f"with {best_circle['circle_size']} members and "
                        f"risk score {best_circle['risk_score']:.3f}"
                    )
                ))

        # Check if both sender and receiver are in the same circle
        sender_circles = {
            c["circle_id"]
            for c in self.graph_engine.get_fraud_circles_for_account(sender_id)
        }
        receiver_circles = {
            c["circle_id"]
            for c in self.graph_engine.get_fraud_circles_for_account(receiver_id)
        }
        shared_circles = sender_circles & receiver_circles
        if shared_circles:
            max_score = min(max_score + 0.3, 1.0)
            indicators.append(FraudIndicator(
                indicator_name="SHARED_FRAUD_CIRCLE",
                indicator_score=0.9,
                details=(
                    f"Both sender and receiver are in the same fraud circle(s): "
                    f"{', '.join(shared_circles)}"
                )
            ))

        return max_score, indicators

    def _analyze_transaction_anomalies(
        self, transaction: Transaction
    ) -> tuple[float, List[FraudIndicator]]:
        """Analyze transaction-level anomalies."""
        indicators = []
        score = 0.0

        # High amount
        if transaction.amount > 50000:
            score += 0.4
            indicators.append(FraudIndicator(
                indicator_name="VERY_HIGH_AMOUNT",
                indicator_score=0.6,
                details=f"Transaction amount ${transaction.amount:,.2f} exceeds \$50,000"
            ))
        elif transaction.amount > 10000:
            score += 0.2
            indicators.append(FraudIndicator(
                indicator_name="HIGH_AMOUNT",
                indicator_score=0.3,
                details=f"Transaction amount ${transaction.amount:,.2f} exceeds \$10,000"
            ))

        # Structuring detection (just below common reporting thresholds)
        if 9000 <= transaction.amount <= 9999:
            score += 0.35
            indicators.append(FraudIndicator(
                indicator_name="POSSIBLE_STRUCTURING",
                indicator_score=0.5,
                details=(
                    f"Amount ${transaction.amount:,.2f} is just below "
                    f"the \$10,000 reporting threshold"
                )
            ))

        # Round amounts (exact hundreds/thousands)
        if transaction.amount >= 1000 and transaction.amount % 1000 == 0:
            score += 0.05
            indicators.append(FraudIndicator(
                indicator_name="ROUND_AMOUNT",
                indicator_score=0.1,
                details=f"Exact round amount: ${transaction.amount:,.2f}"
            ))

        # Self-transaction check
        if transaction.sender_id == transaction.receiver_id:
            score += 0.5
            indicators.append(FraudIndicator(
                indicator_name="SELF_TRANSACTION",
                indicator_score=0.7,
                details="Sender and receiver are the same account"
            ))

        return min(score, 1.0), indicators

    def _analyze_velocity(
        self, account_id: str, current_timestamp
    ) -> tuple[float, List[FraudIndicator]]:
        """Analyze transaction velocity for an account."""
        indicators = []
        score = 0.0

        stats = self.graph_engine.account_stats.get(account_id)
        if not stats:
            return 0.0, []

        timestamps = sorted(stats.get("timestamps", []))
        if len(timestamps) < 3:
            return 0.0, []

        # Count transactions in the last 10 minutes
        from datetime import timedelta
        window = timedelta(minutes=10)
        recent_count = sum(
            1 for ts in timestamps
            if isinstance(current_timestamp - ts, timedelta) and
            current_timestamp - ts <= window
        )

        if recent_count >= 10:
            score += 0.8
            indicators.append(FraudIndicator(
                indicator_name="EXTREME_VELOCITY",
                indicator_score=0.9,
                details=f"{recent_count} transactions in the last 10 minutes"
            ))
        elif recent_count >= 5:
            score += 0.4
            indicators.append(FraudIndicator(
                indicator_name="HIGH_VELOCITY",
                indicator_score=0.5,
                details=f"{recent_count} transactions in the last 10 minutes"
            ))

        return min(score, 1.0), indicators

    def _analyze_network_structure(
        self, sender_id: str, receiver_id: str
    ) -> tuple[float, List[FraudIndicator]]:
        """Analyze network structure around the transaction."""
        indicators = []
        score = 0.0
        graph = self.graph_engine.graph

        # Check for bidirectional relationship (potential layering)
        if graph.has_edge(sender_id, receiver_id) and graph.has_edge(receiver_id, sender_id):
            score += 0.3
            indicators.append(FraudIndicator(
                indicator_name="BIDIRECTIONAL_FLOW",
                indicator_score=0.4,
                details="Bidirectional money flow detected between accounts"
            ))

        # Check sender out-degree (fan-out pattern)
        if graph.has_node(sender_id):
            out_degree = graph.out_degree(sender_id)
            if out_degree > 15:
                score += 0.3
                indicators.append(FraudIndicator(
                    indicator_name="HIGH_FAN_OUT",
                    indicator_score=0.4,
                    details=f"Sender has {out_degree} outgoing connections (fan-out pattern)"
                ))

        # Check receiver in-degree (fan-in / collection pattern)
        if graph.has_node(receiver_id):
            in_degree = graph.in_degree(receiver_id)
            if in_degree > 15:
                score += 0.3
                indicators.append(FraudIndicator(
                    indicator_name="HIGH_FAN_IN",
                    indicator_score=0.4,
                    details=f"Receiver has {in_degree} incoming connections (collection pattern)"
                ))

        # Check for short paths back (potential circular flow)
        try:
            if (graph.has_node(receiver_id) and graph.has_node(sender_id) and
                    receiver_id != sender_id):
                if nx.has_path(graph, receiver_id, sender_id):
                    path_length = nx.shortest_path_length(graph, receiver_id, sender_id)
                    if path_length <= 3:
                        score += 0.4
                        indicators.append(FraudIndicator(
                            indicator_name="SHORT_RETURN_PATH",
                            indicator_score=0.5,
                            details=(
                                f"Short path ({path_length} hops) exists from "
                                f"receiver back to sender (circular flow indicator)"
                            )
                        ))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass

        return min(score, 1.0), indicators

    def _get_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        if score >= 0.75:
            return "CRITICAL"
        elif score >= 0.50:
            return "HIGH"
        elif score >= 0.25:
            return "MEDIUM"
        else:
            return "LOW"

    def _get_recommendation(
        self, score: float, risk_level: str, indicators: List[FraudIndicator]
    ) -> str:
        """Generate a human-readable recommendation."""
        if risk_level == "CRITICAL":
            return (
                "BLOCK TRANSACTION. Multiple critical fraud indicators detected. "
                "Escalate to fraud investigation team immediately."
            )
        elif risk_level == "HIGH":
            return (
                "HOLD TRANSACTION for manual review. Significant fraud risk detected. "
                "Verify account holder identity before processing."
            )
        elif risk_level == "MEDIUM":
            return (
                "FLAG TRANSACTION for monitoring. Some suspicious indicators found. "
                "Allow transaction but add accounts to watchlist."
            )
        else:
            return "ALLOW TRANSACTION. Low fraud risk detected."
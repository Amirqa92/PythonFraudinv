"""
Graph-based fraud detection engine.
Uses NetworkX to build and analyze transaction graphs for fraud circle detection.
"""
import networkx as nx
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set, Optional
import hashlib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FraudGraphEngine:
    """
    Core graph engine that maintains a transaction graph and detects
    fraud circles using cycle detection, community analysis, and
    anomaly scoring.
    """

    def __init__(self):
        # Directed multigraph: allows multiple edges (transactions) between nodes
        self.graph = nx.MultiDiGraph()
        # Store all transactions
        self.transactions: Dict[str, dict] = {}
        # Account-level statistics
        self.account_stats: Dict[str, dict] = defaultdict(lambda: {
            "total_sent": 0.0,
            "total_received": 0.0,
            "send_count": 0,
            "receive_count": 0,
            "unique_counterparties": set(),
            "timestamps": [],
            "ips": set(),
            "devices": set(),
            "amounts": [],
        })
        # Detected fraud circles cache
        self.fraud_circles: List[dict] = []
        self.circle_members: Set[str] = set()
        # Refresh interval for circle detection
        self._last_circle_detection = None
        self._circle_detection_interval = timedelta(seconds=30)
        # Thresholds
        self.RAPID_TRANSACTION_WINDOW = timedelta(minutes=10)
        self.RAPID_TRANSACTION_THRESHOLD = 5
        self.HIGH_AMOUNT_THRESHOLD = 10000
        self.ROUND_TRIP_TIME_WINDOW = timedelta(hours=24)

    def add_transaction(self, transaction: dict) -> None:
        """Add a transaction to the graph."""
        sender = transaction["sender_id"]
        receiver = transaction["receiver_id"]
        tx_id = transaction["transaction_id"]
        amount = transaction["amount"]
        timestamp = transaction["timestamp"]

        # Store transaction
        self.transactions[tx_id] = transaction

        # Add nodes if they don't exist
        if not self.graph.has_node(sender):
            self.graph.add_node(sender, account_type="user", first_seen=timestamp)
        if not self.graph.has_node(receiver):
            self.graph.add_node(receiver, account_type="user", first_seen=timestamp)

        # Add edge (transaction)
        self.graph.add_edge(
            sender, receiver,
            key=tx_id,
            amount=amount,
            timestamp=timestamp,
            tx_type=transaction.get("transaction_type", "transfer"),
            tx_id=tx_id
        )

        # Update account statistics
        self._update_account_stats(sender, receiver, transaction)

        # Trigger circle detection periodically
        self._maybe_detect_circles()

        logger.info(f"Transaction {tx_id}: {sender} -> {receiver} | ${amount:.2f}")

    def _update_account_stats(self, sender: str, receiver: str, tx: dict) -> None:
        """Update account-level statistics."""
        amount = tx["amount"]
        timestamp = tx["timestamp"]

        # Sender stats
        s_stats = self.account_stats[sender]
        s_stats["total_sent"] += amount
        s_stats["send_count"] += 1
        s_stats["unique_counterparties"].add(receiver)
        s_stats["timestamps"].append(timestamp)
        s_stats["amounts"].append(amount)
        if tx.get("sender_ip"):
            s_stats["ips"].add(tx["sender_ip"])
        if tx.get("sender_device_id"):
            s_stats["devices"].add(tx["sender_device_id"])

        # Receiver stats
        r_stats = self.account_stats[receiver]
        r_stats["total_received"] += amount
        r_stats["receive_count"] += 1
        r_stats["unique_counterparties"].add(sender)
        r_stats["timestamps"].append(timestamp)
        r_stats["amounts"].append(amount)
        if tx.get("receiver_ip"):
            r_stats["ips"].add(tx["receiver_ip"])
        if tx.get("receiver_device_id"):
            r_stats["devices"].add(tx["receiver_device_id"])

    def _maybe_detect_circles(self) -> None:
        """Run circle detection if enough time has passed."""
        now = datetime.now()
        if (self._last_circle_detection is None or
                now - self._last_circle_detection > self._circle_detection_interval):
            self.detect_fraud_circles()
            self._last_circle_detection = now

    def detect_fraud_circles(self) -> List[dict]:
        """
        Detect fraud circles using multiple graph algorithms:
        1. Simple cycle detection (direct circular transactions)
        2. Strongly connected components
        3. Community detection for suspicious clusters
        """
        circles = []

        # Method 1: Find simple cycles (limited length to avoid combinatorial explosion)
        cycles_found = self._find_simple_cycles(max_length=8)
        for cycle_nodes in cycles_found:
            circle = self._analyze_circle(cycle_nodes, "simple_cycle")
            if circle and circle["risk_score"] > 0.3:
                circles.append(circle)

        # Method 2: Strongly connected components
        scc_circles = self._find_scc_circles()
        for circle in scc_circles:
            if circle["risk_score"] > 0.3:
                circles.append(circle)

        # Method 3: Detect round-trip transactions (A->B->A)
        roundtrip_circles = self._find_roundtrip_patterns()
        for circle in roundtrip_circles:
            circles.append(circle)

        # Deduplicate circles
        circles = self._deduplicate_circles(circles)

        # Update cached circles and members
        self.fraud_circles = sorted(circles, key=lambda c: c["risk_score"], reverse=True)
        self.circle_members = set()
        for circle in self.fraud_circles:
            self.circle_members.update(circle["members"])

        logger.info(f"Detected {len(self.fraud_circles)} fraud circles "
                     f"involving {len(self.circle_members)} accounts")

        return self.fraud_circles

    def _find_simple_cycles(self, max_length: int = 8) -> List[List[str]]:
        """Find simple cycles in the transaction graph."""
        cycles = []
        try:
            for cycle in nx.simple_cycles(self.graph):
                if 3 <= len(cycle) <= max_length:
                    cycles.append(cycle)
                if len(cycles) > 1000:  # Safety limit
                    break
        except Exception as e:
            logger.warning(f"Cycle detection error: {e}")
        return cycles

    def _find_scc_circles(self) -> List[dict]:
        """Find strongly connected components that indicate fraud rings."""
        circles = []
        sccs = list(nx.strongly_connected_components(self.graph))

        for scc in sccs:
            if len(scc) >= 3:  # At least 3 members to form a circle
                members = list(scc)
                circle = self._analyze_circle(members, "strongly_connected")
                if circle:
                    circles.append(circle)
        return circles

    def _find_roundtrip_patterns(self) -> List[dict]:
        """Find A->B->...->A round-trip money patterns."""
        circles = []
        checked_pairs = set()

        for node in self.graph.nodes():
            successors = set(self.graph.successors(node))
            predecessors = set(self.graph.predecessors(node))

            # Nodes that both send to and receive from this node
            roundtrip_partners = successors & predecessors

            for partner in roundtrip_partners:
                pair = tuple(sorted([node, partner]))
                if pair in checked_pairs:
                    continue
                checked_pairs.add(pair)

                # Analyze the round-trip
                outgoing_edges = self.graph.get_edge_data(node, partner)
                incoming_edges = self.graph.get_edge_data(partner, node)

                if outgoing_edges and incoming_edges:
                    total_out = sum(e["amount"] for e in outgoing_edges.values())
                    total_in = sum(e["amount"] for e in incoming_edges.values())
                    tx_count = len(outgoing_edges) + len(incoming_edges)

                    # Calculate similarity ratio (closer to 1.0 = more suspicious)
                    if max(total_out, total_in) > 0:
                        similarity = min(total_out, total_in) / max(total_out, total_in)
                    else:
                        similarity = 0

                    risk_score = 0.0
                    if similarity > 0.8:
                        risk_score += 0.4
                    if similarity > 0.95:
                        risk_score += 0.2
                    if tx_count > 4:
                        risk_score += 0.2
                    if total_out > self.HIGH_AMOUNT_THRESHOLD:
                        risk_score += 0.2

                    if risk_score > 0.3:
                        circle_id = hashlib.md5(
                            f"roundtrip_{pair}".encode()
                        ).hexdigest()[:12]
                        circles.append({
                            "circle_id": f"RT_{circle_id}",
                            "members": [node, partner],
                            "circle_size": 2,
                            "total_amount": total_out + total_in,
                            "transaction_count": tx_count,
                            "risk_score": min(risk_score, 1.0),
                            "detection_method": "roundtrip",
                            "similarity_ratio": similarity,
                        })

        return circles

    def _analyze_circle(self, members: List[str], detection_method: str) -> Optional[dict]:
        """Analyze a set of members forming a potential fraud circle."""
        if len(members) < 2:
            return None

        total_amount = 0.0
        tx_count = 0
        internal_tx_count = 0
        amounts = []
        member_set = set(members)

        # Analyze transactions within the circle
        for u in members:
            for v in members:
                if u != v and self.graph.has_edge(u, v):
                    edge_data = self.graph.get_edge_data(u, v)
                    for key, data in edge_data.items():
                        total_amount += data["amount"]
                        tx_count += 1
                        internal_tx_count += 1
                        amounts.append(data["amount"])

        if tx_count == 0:
            return None

        # Calculate risk score based on multiple factors
        risk_score = 0.0

        # Factor 1: Circle completeness (how connected are members)
        possible_edges = len(members) * (len(members) - 1)
        if possible_edges > 0:
            completeness = internal_tx_count / possible_edges
            risk_score += completeness * 0.3

        # Factor 2: Amount similarity within circle (structuring indicator)
        if len(amounts) > 1:
            amount_std = np.std(amounts)
            amount_mean = np.mean(amounts)
            if amount_mean > 0:
                cv = amount_std / amount_mean  # Coefficient of variation
                if cv < 0.2:  # Very similar amounts = suspicious
                    risk_score += 0.3
                elif cv < 0.5:
                    risk_score += 0.15

        # Factor 3: High total volume
        if total_amount > self.HIGH_AMOUNT_THRESHOLD * len(members):
            risk_score += 0.2
        elif total_amount > self.HIGH_AMOUNT_THRESHOLD:
            risk_score += 0.1

        # Factor 4: Circle size (larger circles are more suspicious)
        if len(members) >= 5:
            risk_score += 0.2
        elif len(members) >= 3:
            risk_score += 0.1

        # Factor 5: Shared attributes (IPs, devices)
        shared_ips = set()
        shared_devices = set()
        for member in members:
            stats = self.account_stats.get(member)
            if stats:
                shared_ips.update(stats.get("ips", set()) if isinstance(stats, dict) else set())
                shared_devices.update(
                    stats.get("devices", set()) if isinstance(stats, dict) else set()
                )

        # Check IP overlap between members
        ip_sets = []
        for member in members:
            stats = self.account_stats.get(member)
            if stats and stats.get("ips"):
                ip_sets.append(stats["ips"])
        if len(ip_sets) >= 2:
            common_ips = ip_sets[0]
            for ip_set in ip_sets[1:]:
                common_ips = common_ips & ip_set
            if common_ips:
                risk_score += 0.2  # Shared IPs across circle members

        circle_id = hashlib.md5(
            f"{detection_method}_{'_'.join(sorted(members))}".encode()
        ).hexdigest()[:12]

        return {
            "circle_id": f"{detection_method[:3].upper()}_{circle_id}",
            "members": sorted(members),
            "circle_size": len(members),
            "total_amount": round(total_amount, 2),
            "transaction_count": tx_count,
            "risk_score": round(min(risk_score, 1.0), 4),
            "detection_method": detection_method,
        }

    def _deduplicate_circles(self, circles: List[dict]) -> List[dict]:
        """Remove duplicate/subset circles, keeping the highest-scoring ones."""
        if not circles:
            return []

        # Sort by risk score descending
        circles.sort(key=lambda c: c["risk_score"], reverse=True)

        unique_circles = []
        seen_member_sets = []

        for circle in circles:
            member_set = frozenset(circle["members"])
            is_duplicate = False

            for seen_set in seen_member_sets:
                # Check if this circle is a subset of an existing one
                if member_set <= seen_set or seen_set <= member_set:
                    is_duplicate = True
                    break
                # Check high overlap (Jaccard similarity > 0.8)
                intersection = len(member_set & seen_set)
                union = len(member_set | seen_set)
                if union > 0 and intersection / union > 0.8:
                    is_duplicate = True
                    break

            if not is_duplicate:
                unique_circles.append(circle)
                seen_member_sets.append(member_set)

        return unique_circles

    def get_account_risk_score(self, account_id: str) -> float:
        """Calculate risk score for an individual account."""
        if account_id not in self.account_stats:
            return 0.0

        stats = self.account_stats[account_id]
        risk_score = 0.0

        # Factor 1: Part of a fraud circle
        if account_id in self.circle_members:
            # Get max circle risk score for this account
            max_circle_score = max(
                (c["risk_score"] for c in self.fraud_circles
                 if account_id in c["members"]),
                default=0.0
            )
            risk_score += max_circle_score * 0.4

        # Factor 2: Transaction velocity
        timestamps = stats.get("timestamps", [])
        if len(timestamps) >= self.RAPID_TRANSACTION_THRESHOLD:
            sorted_ts = sorted(timestamps)
            for i in range(len(sorted_ts) - self.RAPID_TRANSACTION_THRESHOLD + 1):
                window = sorted_ts[i + self.RAPID_TRANSACTION_THRESHOLD - 1] - sorted_ts[i]
                if isinstance(window, timedelta) and window < self.RAPID_TRANSACTION_WINDOW:
                    risk_score += 0.2
                    break

        # Factor 3: High degree (many counterparties)
        counterparties = stats.get("unique_counterparties", set())
        if len(counterparties) > 20:
            risk_score += 0.15
        elif len(counterparties) > 10:
            risk_score += 0.08

        # Factor 4: Multiple IPs/devices
        ips = stats.get("ips", set())
        devices = stats.get("devices", set())
        if len(ips) > 5:
            risk_score += 0.1
        if len(devices) > 3:
            risk_score += 0.1

        # Factor 5: Amount patterns
        amounts = stats.get("amounts", [])
        if amounts:
            # Check for structuring (amounts just below reporting thresholds)
            structuring_count = sum(1 for a in amounts if 9000 <= a <= 9999)
            if structuring_count >= 3:
                risk_score += 0.25

            # Large transaction volume
            total = stats.get("total_sent", 0) + stats.get("total_received", 0)
            if total > 100000:
                risk_score += 0.1

        # Factor 6: Send/receive imbalance
        total_sent = stats.get("total_sent", 0)
        total_received = stats.get("total_received", 0)
        if total_sent + total_received > 0:
            imbalance = abs(total_sent - total_received) / (total_sent + total_received)
            if imbalance > 0.9:  # Almost all one direction
                risk_score += 0.1

        return round(min(risk_score, 1.0), 4)

    def get_fraud_circles_for_account(self, account_id: str) -> List[dict]:
        """Get all fraud circles that include a specific account."""
        return [
            circle for circle in self.fraud_circles
            if account_id in circle["members"]
        ]

    def get_graph_stats(self) -> dict:
        """Get overall graph statistics."""
        risk_scores = [
            self.get_account_risk_score(node) for node in self.graph.nodes()
        ]
        avg_score = np.mean(risk_scores) if risk_scores else 0.0
        high_risk_count = sum(1 for s in risk_scores if s > 0.6)

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "total_transactions": len(self.transactions),
            "detected_circles": len(self.fraud_circles),
            "high_risk_accounts": high_risk_count,
            "avg_fraud_score": round(float(avg_score), 4),
            "top_fraud_circles": self.fraud_circles[:10],
        }
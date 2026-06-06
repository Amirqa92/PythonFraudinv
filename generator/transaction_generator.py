import random
import string
import uuid
import time
import requests
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging

from starlette.config import Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class TransactionGenerator:
    """
      Generates realistic transaction data with embedded fraud patterns:
      1. Circular transactions (A->B->C->A)
      2. Layering patterns (fan-out, fan-in)
      3. Structuring (amounts just below reporting thresholds)
      4. Round-trip transactions
      5. Rapid-fire transactions
      6. Normal legitimate transactions
      """
    def __init__(self, api_url: str ="http://localhost:8000"):
        self.api_url = api_url
        self.score_endpoint = f"{api_url}/api/v1/transactions/score"
        self.stats_endpoint = f"{api_url}/api/v1/graph/stats"
        self.health_endpoint = f"{api_url}/api/v1/health"

        self.legitimate_accounts: List[str] = []
        self.fraud_ring_1: List[str] = []  # Circular fraud ring
        self.fraud_ring_2: List[str] = []  # Layering ring
        self.fraud_ring_3: List[str] = []  # Structuring ring
        self.mule_accounts: List[str] = []
        self.all_accounts: List[str] = []

        # IP address pools
        self.legitimate_ips: List[str] = []
        self.shared_fraud_ip_pool: List[str] = []

        # Device pools
        self.device_pool: Dict[str, str] = {}

        # Transaction counter
        self.tx_counter = 0
        self.base_time = datetime.now() - timedelta(hours=2)

        self._initialize_accounts()

    def _initialize_accounts(self):
        """Initialize account pools."""
        self.legitimate_accounts = [f"LEGIT_{i:04d}" for i in range(50)]
        self.fraud_ring_1 = [f"RING1_{i:03d}" for i in range (5)]
        self.fraud_ring_2 = [f"RING2_{i:03d}" for i in range (7)]
        self.fraud_ring_3 = [f"RING3_{i:03d}" for i in range (4)]
        self.mule_accounts = [f"MULE_{i:03d}" for i in range(3)]

        self.all_accounts = (
                self.legitimate_accounts +
                self.fraud_ring_1 +
                self.fraud_ring_2 +
                self.fraud_ring_3 +
                self.mule_accounts
        )
        self.legitimate_ips = [(f"192.168.{random.randint(0,255)}."
                                f"{random.randint(0,255)}")
                               for _ in range(30)]
        self.shared_fraud_ip_pool = [(f"10.0.{random.randint(0,255)}."
                                f"{random.randint(0,255)}")
                               for _ in range(3)]

        for account in self.all_accounts:
            self.device_pool[account] = f"DEV_{uuid.uuid4().hex[:8]}"

        shared_device = f"DEV_SHARED_{uuid.uuid4().hex[:6]}"
        for account in self.fraud_ring_1[:3]:
            self.device_pool[account] = shared_device

        logger.info(
            f"Initialized {len(self.all_accounts)} accounts: "
            f"{len(self.legitimate_accounts)} legitimate, "
            f"{len(self.fraud_ring_1)} ring1, "
            f"{len(self.fraud_ring_2)} ring2, "
            f"{len(self.fraud_ring_3)} ring3, "
            f"{len(self.mule_accounts)} mules"
        )
    def _get_next_timestamp(self,jitter_seconds: int = 60  ) -> datetime:
        self.base_time += timedelta(seconds=random.randint(1,jitter_seconds ))
        return self.base_time

    def _create_transaction(
            self,
            amount: float,
            sender: str,
            recipient: str,
            tx_type:str = "transfer",
            sender_ip: Optional[str] = None,
            recipient_ip: Optional[str] = None,
            timestamp: Optional[datetime] = None,
            description: Optional[str] = None,
    ) -> dict:
        self.tx_counter += 1
        tx_id = f"TX_{self.tx_counter:06d}_{uuid.uuid4().hex[:8]}"
        if timestamp is None:
            timestamp = self._get_next_timestamp()
        if sender_ip is None:
            if sender in self.fraud_ring_1 or sender in self.fraud_ring_2:
                sender_ip = random.choice(self.shared_fraud_ip_pool)
            else:
                sender_ip = random.choice(self.legitimate_ips)
        if recipient_ip is None:
            if recipient in self.fraud_ring_1 or recipient in self.fraud_ring_2:
                recipient_ip = random.choice(self.shared_fraud_ip_pool)
            else:
                recipient_ip = random.choice(self.legitimate_ips)

        return {
            "transaction_id" : tx_id,
            "amount" : amount,
            "sender_id" : sender,
            "recipient_id" : recipient,
            "timestamp": timestamp,
            "sender_ip" : sender_ip,
            "recipient_ip" : recipient_ip,
            "transaction_type" : tx_type,
            "currency" : "USD",
            "sender_device_id" : self.device_pool.get(sender, f"DEV_{sender}"),
            "recipient_device_id" : self.device_pool.get(recipient, f"DEV_{recipient}"),
            "description" : description
        }

    def _generate_legitimate_transactions(
            self,
            count: int = 20,
    ) -> list[dict]:
        transactions = []
        for _ in range(count):
            sender = random.choice(self.legitimate_accounts)
            recipient = random.choice([t for t in self.legitimate_accounts if t != sender])
            amount = round(random.choice(
                [
                    random.uniform(10,500),
                    random.uniform(500,2000),
                    random.uniform(2000,8000),
                    random.uniform(50,200),
                ]
            ),2)

            tx = self._create_transaction(
                amount,
                sender,
                recipient,
                tx_type="transfer"
            )
            transactions.append(tx)
        return transactions

    def _generate_circular_fraud( self,):
        transactions = []
        ring = self.fraud_ring_1
        # Cycle through all ring members and wrap back to start
        amount = round(random.uniform(5000, 9999), 2)  # structuring range
        for i, sender in enumerate(ring):
            recipient = ring[(i + 1) % len(ring)]
            # Slightly decay amount each hop to simulate layering
            hop_amount = round(amount * random.uniform(0.92, 0.99), 2)
            tx = self._create_transaction(
                hop_amount,
                sender,
                recipient,
                tx_type="transfer",
                sender_ip=random.choice(self.shared_fraud_ip_pool),
                recipient_ip=random.choice(self.shared_fraud_ip_pool),
                description=f"circular_hop_{i}",
            )
            transactions.append(tx)
        return transactions




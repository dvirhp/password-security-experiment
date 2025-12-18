import time
from collections import defaultdict

from configuration import rate_limit_parameters


class RateLimiter:
    def __init__(self, rate_limit_params=None):
        self._rate_limit_parameters = rate_limit_params or rate_limit_parameters

        self._max_tokens = self._rate_limit_parameters["tokens"]
        self._refill_rate_tps = self._rate_limit_parameters["refill_rate_tps"]

        self._buckets = defaultdict(
            lambda: {
                "tokens": self._max_tokens,
                "last_refill": time.perf_counter()
            }
        )

    def _refill(self, bucket):
        now = time.perf_counter()
        elapsed = now - bucket["last_refill"]

        refill_amount = elapsed * self._refill_rate_tps

        if refill_amount > 0:
            bucket["tokens"] = min(self._max_tokens, bucket["tokens"] + refill_amount)
            bucket["last_refill"] = now

    def allow_request(self, ip_address) -> bool:
        bucket = self._buckets[ip_address]

        self._refill(bucket)

        if bucket["tokens"] < 1:
            return False

        bucket["tokens"] -= 1
        return True

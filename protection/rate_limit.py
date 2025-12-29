"""
RateLimiter Module

Implements a token-bucket based rate limiter for controlling request frequency per IP.
"""

import time
from collections import defaultdict

from configuration import rate_limit_parameters


class RateLimiter:
    """
    Token-bucket rate limiter.

    Each IP address has its own token bucket.
    Tokens are consumed per request and replenished over time at a fixed rate.
    """

    def __init__(self, parameters=None):
        """
        Initialize the RateLimiter with optional parameters.

        Args:
            parameters (dict, optional): Rate limiter configuration. Expected keys:
                - "tokens": Maximum number of tokens per bucket.
                - "refill_rate_tps": Token refill rate in tokens per second.
        """
        self._rate_limit_parameters = parameters or rate_limit_parameters

        self._max_tokens = self._rate_limit_parameters["tokens"]
        self._refill_rate_tps = self._rate_limit_parameters["refill_rate_tps"]

        self._buckets = defaultdict(
            lambda: {
                "tokens": self._max_tokens,
                "last_refill": time.perf_counter()
            }
        )

    def _refill(self, bucket):
        """
        Refill tokens in a bucket based on elapsed time.

        Args:
            bucket (dict): Bucket containing 'tokens' and 'last_refill'.
        """
        now = time.perf_counter()
        elapsed = now - bucket["last_refill"]

        refill_amount = elapsed * self._refill_rate_tps

        if refill_amount > 0:
            bucket["tokens"] = min(self._max_tokens, bucket["tokens"] + refill_amount)
            bucket["last_refill"] = now

    def allow_request(self, ip_address) -> bool:
        """
        Check if a request from the given IP address is allowed.

        This method consumes one token if available, and returns False if the bucket is empty.

        Args:
            ip_address (str): The IP address making the request.

        Returns:
            bool: True if the request is allowed, False if rate-limited.
        """
        bucket = self._buckets[ip_address]

        self._refill(bucket)

        if bucket["tokens"] < 1:
            return False

        bucket["tokens"] -= 1
        return True

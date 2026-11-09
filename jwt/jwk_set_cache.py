import time
from typing import Any, Optional, Union

from .api_jwk import PyJWKSet, PyJWTSetWithTimestamp
from .exceptions import PyJWKSetError


class JWKSetCache:
    def __init__(self, lifespan: float) -> None:
        self.jwk_set_with_timestamp: Optional[PyJWTSetWithTimestamp] = None
        self.lifespan = lifespan

    def put(self, jwk_set: Optional[Union[PyJWKSet, dict[str, Any]]]) -> None:
        """Publish *jwk_set* as a single new generation, or clear the cache.

        Accepts either an already-parsed ``PyJWKSet`` or the raw JWKS
        payload it is parsed from, and always stores it parsed so that
        reads never have to parse the keys again.

        A successful call atomically replaces the previously published
        generation. Keys cached against an older generation can therefore
        never be served from the new one: a removed ``kid`` stays removed,
        and a ``kid`` whose material changed resolves to the new key.
        Failed fetches must not call this method, so a still-valid cached
        generation (and its original expiry time) is left untouched.

        :raises PyJWKSetError: If *jwk_set* is neither a ``PyJWKSet`` nor a
            JWKS payload containing usable keys.
        """
        if jwk_set is None:
            # clear cache
            self.jwk_set_with_timestamp = None
            return

        if not isinstance(jwk_set, PyJWKSet):
            if not isinstance(jwk_set, dict):
                raise PyJWKSetError("Invalid JWK Set value")
            jwk_set = PyJWKSet.from_dict(jwk_set)

        # Build the full generation before swapping the reference so readers
        # never observe a partially published JWK Set.
        new_generation = PyJWTSetWithTimestamp(jwk_set)
        self.jwk_set_with_timestamp = new_generation

    def get_entry(self) -> Optional[PyJWTSetWithTimestamp]:
        """Return the currently valid generation, or ``None``.

        The returned :class:`PyJWTSetWithTimestamp` is the unit per-key
        caches are bound to: it is ``None`` when no JWK Set has been
        published or when the published generation has expired, in which
        case callers must fetch a new generation instead of reusing old
        key material.
        """
        if self.jwk_set_with_timestamp is None or self.is_expired():
            return None

        return self.jwk_set_with_timestamp

    def get(self) -> Optional[PyJWKSet]:
        entry = self.get_entry()
        if entry is None:
            return None

        return entry.get_jwk_set()

    def is_expired(self) -> bool:
        return (
            self.jwk_set_with_timestamp is not None
            and self.lifespan > -1
            and time.monotonic()
            > self.jwk_set_with_timestamp.get_timestamp() + self.lifespan
        )

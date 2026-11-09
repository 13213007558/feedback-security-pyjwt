from __future__ import annotations

import http.client
import json
import math
import threading
import time
import urllib.request
from collections import OrderedDict
from ssl import SSLContext
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientConnectionError, PyJWKClientError
from .jwk_set_cache import JWKSetCache


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


class PyJWKClient:
    def __init__(
        self,
        uri: str,
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        cache_jwk_set: bool = True,
        lifespan: float = 300,
        headers: dict[str, Any] | None = None,
        timeout: float = 30,
        ssl_context: SSLContext | None = None,
        cooldown_duration: float = 30,
    ):
        """A client for retrieving signing keys from a JWKS endpoint.

        ``PyJWKClient`` uses a two-tier caching system to avoid unnecessary
        network requests:

        **Tier 1 — JWK Set cache** (enabled by default):
        Caches the entire JSON Web Key Set response from the endpoint.
        Controlled by:

        - ``cache_jwk_set``: Set to ``True`` (the default) to enable this
          cache. When enabled, the JWK Set is fetched from the network only
          when the cache is empty or expired.
        - ``lifespan``: Time in seconds before the cached JWK Set expires.
          Defaults to ``300`` (5 minutes). Must be greater than 0.

        Unknown key IDs can trigger one forced refresh after the cooldown
        period configured by ``cooldown_duration``. Every successful fetch
        starts this cooldown, including the initial fetch and cache-expiry
        fetches. A newly rotated key may therefore wait for the cooldown
        period before it is fetched; set ``cooldown_duration`` to ``0`` to
        disable this behavior. The cooldown is bypassed when
        ``cache_jwk_set`` is ``False``.

        **Tier 2 — Signing key cache** (disabled by default):
        Caches individual signing keys (looked up by ``kid``) using an LRU
        cache. Every cached key belongs to exactly one published JWK Set
        generation and is held no longer than that generation's
        ``lifespan``: refreshing the set atomically starts a new
        generation, after which a removed ``kid`` fails and rotated
        material resolves to the new key. Keys are also evicted when the
        cache reaches its maximum size. Because there is no generation to
        bind to when Tier 1 is disabled, this cache is only active while
        ``cache_jwk_set`` is ``True``. Controlled by:

        - ``cache_keys``: Set to ``True`` to enable this cache. Has no
          effect when ``cache_jwk_set`` is ``False``. Defaults to
          ``False``.
        - ``max_cached_keys``: Maximum number of signing keys to keep in
          the LRU cache. Defaults to ``16``.

        :param uri: The URL of the JWKS endpoint.
        :type uri: str
        :param cache_keys: Enable the per-key LRU cache (Tier 2).
        :type cache_keys: bool
        :param max_cached_keys: Max entries in the signing key LRU cache.
        :type max_cached_keys: int
        :param cache_jwk_set: Enable the JWK Set response cache (Tier 1).
        :type cache_jwk_set: bool
        :param lifespan: TTL in seconds for the JWK Set cache.
        :type lifespan: float
        :param headers: Optional HTTP headers to include in requests.
        :type headers: dict or None
        :param timeout: HTTP request timeout in seconds.
        :type timeout: float
        :param ssl_context: Optional SSL context for the request.
        :type ssl_context: ssl.SSLContext or None
        :param cooldown_duration: Minimum time in seconds between forced
            refreshes after an unknown key ID. Defaults to ``30``.
        :type cooldown_duration: float
        """
        if headers is None:
            headers = {}
        # urllib's default OpenerDirector also handles file://, ftp://, and
        # data: URIs. Reject anything that isn't http(s) eagerly so a caller
        # passing an attacker-influenced URL (e.g. taken from a `jku` token
        # header) can't read local files or reach other unintended schemes.
        scheme = urlparse(uri).scheme.lower()
        if scheme not in ("http", "https"):
            raise PyJWKClientError(
                f"Invalid JWKS URI scheme {scheme!r}: only 'http' and 'https' "
                f"are supported."
            )
        self.uri = uri
        self.jwk_set_cache: JWKSetCache | None = None
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context
        if cooldown_duration < 0:
            raise PyJWKClientError(
                "Cooldown duration must be greater than or equal to 0, "
                f'the input is "{cooldown_duration}"'
            )
        if not math.isfinite(cooldown_duration):
            raise PyJWKClientError(
                f'Cooldown duration must be finite, the input is "{cooldown_duration}"'
            )
        self.cooldown_duration = cooldown_duration
        self._last_successful_fetch: float | None = None
        self._client_lock = threading.RLock()

        if cache_jwk_set:
            # Init jwt set cache with default or given lifespan.
            # Default lifespan is 300 seconds (5 minutes).
            if lifespan <= 0:
                raise PyJWKClientError(
                    f'Lifespan must be greater than 0, the input is "{lifespan}"'
                )
            self.jwk_set_cache = JWKSetCache(lifespan)
        else:
            self.jwk_set_cache = None

        self._cache_keys = cache_keys
        self._max_cached_keys = max_cached_keys
        # kid -> (generation entry, resolved PyJWK). Only populated while a
        # JWK Set cache is active, since an entry is the TTL-bearing unit
        # the key cache is bound to.
        self._signing_key_cache: OrderedDict[str, tuple[Any, PyJWK]] = OrderedDict()

    def fetch_data(self) -> Any:
        """Fetch the JWK Set from the JWKS endpoint.

        Makes an HTTP request to the configured ``uri`` and returns the
        parsed JSON response. The response is validated before it is
        returned; publication into the JWK Set cache happens afterwards via
        :meth:`get_jwk_set`, so a network or parsing failure never replaces
        or extends a still-valid cached generation.

        :returns: The parsed JWK Set as a dictionary.
        :raises PyJWKClientConnectionError: If the HTTP request fails.
        :raises PyJWKClientError: If the endpoint does not return a JSON
            object.
        :raises PyJWKSetError: If the JWK Set cache is enabled and the
            response contains no usable keys.
        """
        try:
            r = urllib.request.Request(url=self.uri, headers=self.headers)
            handlers: list[Any] = [_NoRedirectHandler()]
            if self.ssl_context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(r, timeout=self.timeout) as response:
                jwk_set = json.load(response)
        except (URLError, TimeoutError, http.client.HTTPException) as e:
            if isinstance(e, HTTPError):
                e.close()
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{e}"'
            ) from e

        # Validate the payload before it reaches the cache, so an endpoint
        # returning something that isn't a JSON object is reported as such
        # rather than as a malformed JWK Set.
        jwk_set = self._as_jwk_set_payload(jwk_set)

        self._last_successful_fetch = time.monotonic()
        return jwk_set

    def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        """Return the JWK Set, using the cache when available.

        :param refresh: Force a fresh fetch from the endpoint, bypassing
            the cache.
        :type refresh: bool
        :returns: The JWK Set.
        :rtype: PyJWKSet
        :raises PyJWKClientError: If the endpoint does not return a JSON
            object.
        """
        with self._client_lock:
            data = None
            if self.jwk_set_cache is not None and not refresh:
                data = self.jwk_set_cache.get()

            if data is not None:
                # A cache hit is already parsed, so serve it as-is.
                return data

        # Perform the network round-trip without holding the lock so other
        # readers can keep using the current generation while we fetch.
        # Anything raised here happens before publication, leaving any
        # cached generation (and its original expiry) untouched.
        data = self.fetch_data()

        # A subclass may return an already-parsed, possibly transformed
        # PyJWKSet; only raw payloads need parsing here.
        if isinstance(data, PyJWKSet):
            jwk_set = data
        else:
            jwk_set = PyJWKSet.from_dict(self._as_jwk_set_payload(data))

        with self._client_lock:
            if self.jwk_set_cache is not None:
                # Publish one complete generation atomically. Cache the
                # value actually being returned (post-subclass-transform),
                # so later cache hits serve exactly this key set.
                self.jwk_set_cache.put(jwk_set)
                self._signing_key_cache.clear()

        return jwk_set

    @staticmethod
    def _as_jwk_set_payload(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise PyJWKClientError("The JWKS endpoint did not return a JSON object")

        return data

    def get_signing_keys(self, refresh: bool = False) -> list[PyJWK]:
        """Return all signing keys from the JWK Set.

        Filters the JWK Set to keys whose ``use`` is ``"sig"`` (or
        unspecified) and that have a ``kid``.

        :param refresh: Force a fresh fetch from the endpoint, bypassing
            the cache.
        :type refresh: bool
        :returns: A list of signing keys.
        :rtype: list[PyJWK]
        :raises PyJWKClientError: If no signing keys are found.
        """
        jwk_set = self.get_jwk_set(refresh)
        return self._get_signing_keys_from_jwk_set(jwk_set)

    @staticmethod
    def _get_signing_keys_from_jwk_set(jwk_set: PyJWKSet) -> list[PyJWK]:
        signing_keys = [
            jwk_set_key
            for jwk_set_key in jwk_set.keys
            if jwk_set_key.public_key_use in ["sig", None] and jwk_set_key.key_id
        ]

        if not signing_keys:
            raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")

        return signing_keys

    def get_signing_key(self, kid: str) -> PyJWK:
        """Return the signing key matching the given ``kid``.

        If no match is found in the current JWK Set, the set is refreshed
        from the endpoint and the lookup is retried once when the refresh
        cooldown permits it.

        When ``cache_keys`` is enabled, a resolved key is cached only for
        the JWK Set generation it came from and only while that generation
        is within its lifespan. A refresh publishes a new generation, so a
        revoked ``kid`` raises rather than returning the stale key and a
        rotated ``kid`` returns the replacement key.

        :param kid: The key ID to look up.
        :type kid: str
        :returns: The matching signing key.
        :rtype: PyJWK
        :raises PyJWKClientError: If no matching key is found after
            refreshing.
        """
        with self._client_lock:
            cached_key = self._get_cached_signing_key(kid)
            if cached_key is not None:
                return cached_key

            entry, signing_keys = self._get_current_signing_keys()
            signing_key = self.match_kid(signing_keys, kid)

            if not signing_key:
                cooling_down = (
                    self.jwk_set_cache is not None
                    and self._last_successful_fetch is not None
                    and time.monotonic() - self._last_successful_fetch
                    < self.cooldown_duration
                )
                if not cooling_down:
                    signing_keys = self.get_signing_keys(refresh=True)
                    self._last_successful_fetch = time.monotonic()
                    entry = self._get_current_generation_entry()
                    signing_key = self.match_kid(signing_keys, kid)

                if not signing_key:
                    raise PyJWKClientError(
                        f'Unable to find a signing key that matches: "{kid}"'
                    )

            self._cache_signing_key(kid, entry, signing_key)
            return signing_key

    def _get_current_generation_entry(self) -> Any:
        if self.jwk_set_cache is None:
            return None
        return self.jwk_set_cache.get_entry()

    def _get_current_signing_keys(self) -> tuple[Any, list[PyJWK]]:
        jwk_set = self.get_jwk_set()
        entry = self._get_current_generation_entry()
        return entry, self._get_signing_keys_from_jwk_set(jwk_set)

    def _get_cached_signing_key(self, kid: str) -> PyJWK | None:
        if not self._cache_keys or self.jwk_set_cache is None:
            return None

        cached = self._signing_key_cache.get(kid)
        if cached is None:
            return None

        entry, signing_key = cached
        # Entries belong to one generation. A published replacement invalidates
        # the whole key cache, and an expired generation must not be trusted.
        if entry is not self._get_current_generation_entry():
            del self._signing_key_cache[kid]
            return None

        self._signing_key_cache.move_to_end(kid)
        return signing_key

    def _cache_signing_key(self, kid: str, entry: Any, signing_key: PyJWK) -> None:
        if not self._cache_keys or self.jwk_set_cache is None or entry is None:
            return

        # Never reinsert a key from a generation that has been superseded or
        # expired while a fetch was in flight.
        if entry is not self._get_current_generation_entry():
            return

        self._signing_key_cache[kid] = (entry, signing_key)
        self._signing_key_cache.move_to_end(kid)
        while len(self._signing_key_cache) > self._max_cached_keys:
            self._signing_key_cache.popitem(last=False)

    def get_signing_key_from_jwt(self, token: str | bytes) -> PyJWK:
        """Return the signing key for a JWT by reading its ``kid`` header.

        Extracts the ``kid`` from the token's unverified header and
        delegates to :meth:`get_signing_key`.

        :param token: The encoded JWT.
        :type token: str or bytes
        :returns: The matching signing key.
        :rtype: PyJWK
        """
        unverified = decode_token(token, options={"verify_signature": False})
        header = unverified["header"]
        return self.get_signing_key(header.get("kid"))

    @staticmethod
    def match_kid(signing_keys: list[PyJWK], kid: str) -> PyJWK | None:
        """Find a key in *signing_keys* that matches *kid*.

        :param signing_keys: The list of keys to search.
        :type signing_keys: list[PyJWK]
        :param kid: The key ID to match.
        :type kid: str
        :returns: The matching key, or ``None`` if not found.
        :rtype: PyJWK or None
        """
        signing_key = None

        for key in signing_keys:
            if key.key_id == kid:
                signing_key = key
                break

        return signing_key

# Time-based HOTP/TOTP implementation
# @SEE: https://datatracker.ietf.org/doc/html/rfc6238
# @SEE: https://datatracker.ietf.org/doc/html/rfc4226
from typing import List

import unicodedata
import hmac
from datetime import datetime


class TOTP:
    DEFAULT_TIME_STEP = 30
    DEFAULT_TIME_START = 0

    def __init__(
        self,
        secret: bytes,
        digest: str = "sha1",
        digits: int = 6
    ):
        """
        Instantiate with the desired shared secret and digest for producing hashes based on time,
        with an optional digits to convert and truncate the result to for easier entry.
        If digits is 0, then truncation is implicitly disabled.
        """
        self.secret = secret
        self.digest = digest
        self.digits = digits

    @staticmethod
    def _int_to_bytearray(i: int, padding: int = 8) -> bytearray:
        """
        Convert an integer to a bytearray to feed to the HMAC digest
        function alongside the shared secret.
        """
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        return bytearray(reversed(result)).rjust(padding, b"\0")

    @staticmethod
    def _when_as_int(when: int | datetime | None) -> int:
        """
        Return when as an integer number of seconds since
        the linux epoch relative to the specified time (if datetime)
        or now (if None). Return unaltered if passed anything else.
        """
        if when is None:
            when = int(datetime.now().timestamp())
        if isinstance(when, datetime):
            when = int(when.timestamp())

        return when

    def _truncate_hmac(self, digested: bytearray) -> str:
        """
        Truncate our hmac into a series of digits for easier entry by a human user.
        """
        if not self.digits:
            raise ValueError("Cannot truncate when digits is not set to a valid integer.")

        offset = digested[-1] & 0xF
        code = (
            (digested[offset] & 0x7F) << 24
            | (digested[offset + 1] & 0xFF) << 16
            | (digested[offset + 2] & 0xFF) << 8
            | (digested[offset + 3] & 0xFF)
        )
        str_code = str(10_000_000_000 + (code % 10 ** self.digits))
        return str_code[-self.digits:]

    def at(
        self,
        when: int|datetime|None = None,
        time_step: int = DEFAULT_TIME_STEP,
        time_start: int = DEFAULT_TIME_START,
        truncate: bool = True,
    ) -> str:
        """
        Generate a single OTP at the specified time/value.
        Returns truncated digest digits if self.digits is not 0 and `truncate` is True;
        otherwise, returns the hex representation of the digest.
        """
        when = TOTP._when_as_int(when)
        tyme = int((when - time_start) / time_step)
        if not self.digits or not truncate:
            return hmac.digest(self.secret, TOTP._int_to_bytearray(tyme), self.digest).hex()
        return self._truncate_hmac(bytearray(hmac.digest(self.secret, TOTP._int_to_bytearray(tyme), self.digest)))

    def range(
        self,
        when: int|datetime|None = None,
        time_step: int = DEFAULT_TIME_STEP,
        time_start: int = DEFAULT_TIME_START,
        window: int = 0,
        truncate: bool = True
    ) -> List[str]:
        """
        Generate a list of acceptable otps going back into the past and future,
        based on the `when` datetime and the range window.
        """
        when = TOTP._when_as_int(when)
        results = []
        for idx in range(-window, window+1):
            results.append(self.at(when - time_step * idx, time_step, time_start, truncate))

        return results

    def verify(
        self,
        code: str,
        when: int|datetime|None = None,
        time_step: int = DEFAULT_TIME_STEP,
        time_start: int = DEFAULT_TIME_START,
        truncate: bool = True,
        window: int = 0,
    ) -> bool:
        """
        Compare the specified `code` to valid values within the specified window range.
        If any of them match, we return True; otherwise, False.
        We purposely waste a little time comparing every character vs a short-circuiting comparison (`==`)
        to prevent timing-based oracle attacks, by normalizing and hashing, and then comparing
        hashes of the offered code and the allowable code(s).
        """
        codes = self.range(when, time_step, time_start, window, truncate)
        for comp in codes:
            offered = unicodedata.normalize("NFKC", code)
            allowed = unicodedata.normalize("NFKC", comp)
            if hmac.compare_digest(offered.encode("utf-8"), allowed.encode("utf-8")):
                return True
        return False

    def expires(
        self,
        when: int|datetime|None = None,
        time_step: int = DEFAULT_TIME_STEP,
        time_start: int = DEFAULT_TIME_START,
    ) -> int:
        """
        Seconds remaining until the current code will expire - that is, when the specified time_step will
        cause us to move to the next window.
        """
        when = TOTP._when_as_int(when)
        return time_step - int((when - time_start) % time_step)

import math
import secrets
import string


def calculate_entropy(length: int, pool_size: int) -> float:
    if pool_size <= 0 or length <= 0:
        return 0.0
    return length * math.log2(pool_size)


# Generator global configuration constants
MIN_LENGTH = 8
MAX_LENGTH = 128
AMBIGUOUS = set("Il1O0o")


def generate_password(
    length: int,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:

    # 1. Early validation of length limits
    if length < MIN_LENGTH:
        raise ValueError(f"The password must be at least {MIN_LENGTH} characters long.")

    if length > MAX_LENGTH:
        raise ValueError("The password must have a maximum of 128 characters.")

    symbols = "!@#$%&*-_+=?"

    char_pools = [
        (use_upper, string.ascii_uppercase),
        (use_lower, string.ascii_lowercase),
        (use_digits, string.digits),
        (use_symbols, symbols),
    ]

    # We filter and obtain only the pools that the user activated
    pools = [chars for enabled, chars in char_pools if enabled]

    # We validate that at least one pool has been activated
    if not pools:
        raise ValueError("At least one parameter must be selected.")

    # 2. Filtering of ambiguous characters if the option is enabled
    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]

    # 3. We guarantee at least one character from each active pool.
    password = [secrets.choice(chars) for chars in pools]

    # 4. We fill in the rest of the required length
    all_chars = "".join(pools)
    password += [secrets.choice(all_chars) for _ in range(length - len(password))]

    # 5. We cryptographically secure shuffle to break predictable patterns
    secrets.SystemRandom().shuffle(password)

    return "".join(password)

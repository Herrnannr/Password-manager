import math
import secrets
import string

# --- Constants ---
MIN_LENGTH = 8
MAX_LENGTH = 128
AMBIGUOUS = set("Il1O0o")
SYMBOLS = "!@#$%&*-_+=?"


# --- Internal Helpers ---
def _get_active_pools(
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    avoid_ambiguous: bool,
) -> list[str]:

    char_pools = [
        (use_upper, string.ascii_uppercase),
        (use_lower, string.ascii_lowercase),
        (use_digits, string.digits),
        (use_symbols, SYMBOLS),
    ]

    pools = [chars for enabled, chars in char_pools if enabled]

    if not pools:
        raise ValueError("At least one parameter must be selected.")

    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]

    return pools


def calculate_entropy(
    length: int,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> float:
    if length <= 0:
        return 0.0

    try:
        pools = _get_active_pools(
            use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous
        )
    except ValueError:
        return 0.0

    pool_size = len("".join(pools))
    return length * math.log2(pool_size)


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
        raise ValueError(
            f"The password must have a maximum of {MAX_LENGTH} characters."
        )

    # Get filtered pools using the shared helper
    pools = _get_active_pools(
        use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous
    )

    # length must be at least equal to the number of mandatory categories
    if length < len(pools):
        raise ValueError(
            f"Length must be at least {len(pools)} to include all active character categories."
        )

    # 2. Guarantee at least one character from each active pool
    password = [secrets.choice(chars) for chars in pools]

    # 3. Fill in the rest of the required length
    all_chars = "".join(pools)
    password += [secrets.choice(all_chars) for _ in range(length - len(password))]

    # 4. Cryptographically secure shuffle to break predictable patterns
    secrets.SystemRandom().shuffle(password)

    return "".join(password)

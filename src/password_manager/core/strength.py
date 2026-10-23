from zxcvbn import zxcvbn

THRESHOLD_LEVEL_1 = 30.0
THRESHOLD_LEVEL_2 = 55.0
THRESHOLD_LEVEL_3 = 75.0

MAX_ZXCVBN_LENGTH = 100

def evaluate_entropy_score(entropy_result: float) -> int:

    if entropy_result <= 0:
        return 0
    elif entropy_result < THRESHOLD_LEVEL_1:
        return 1
    elif entropy_result < THRESHOLD_LEVEL_2:
        return 2
    elif entropy_result < THRESHOLD_LEVEL_3:
        return 3
    else:
        return 4


def evaluate_manual_strength(password: str, user_inputs: list[str] | None = None ) -> int:
    if not password:
        return 0

    trimmed_password = password[:MAX_ZXCVBN_LENGTH]
    result = zxcvbn(trimmed_password)
    
    return result["score"]
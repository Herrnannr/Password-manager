from zxcvbn import zxcvbn


def evaluate_entropy_score(entropy_result: float) -> int:

    if entropy_result <= 0:
        return 0
    elif entropy_result < 30:
        return 1
    elif entropy_result < 55:
        return 2
    elif entropy_result < 75:
        return 3
    else:
        return 4


def evaluate_manual_strength(password: str) -> int:
    result = zxcvbn(password)
    return result["score"]
import pytest

from password_manager.core.generator import generate_password
from password_manager.core.strength import (
    evaluate_entropy_score,
    evaluate_manual_strength,
)


@pytest.mark.parametrize(
    "entropy_bits, expected_score",
    [
        (0.0, 0),
        (-1.0, 0),
        (29.99, 1),
        (30.0, 2),
        (54.99, 2),
        (55.0, 3),
        (74.99, 3),
        (75.0, 4),
        (127.99, 4)
    ]
)
def test_evaluate_entropy_score(entropy_bits, expected_score):
    result = evaluate_entropy_score(entropy_bits)
    assert result == expected_score


@pytest.mark.parametrize("password",["12345678", "password"])
def test_evaluate_manual_strength_weak_password(password):
    result = evaluate_manual_strength(password)
    assert isinstance(result, int)
    assert result <= 1


def test_evaluate_manual_strength_empty_string():
    result = evaluate_manual_strength("")
    assert result == 0


def test_evaluate_manual_strength_strong_generated_passwords():
    for _ in range(50):
        password = generate_password(20)
        result = evaluate_manual_strength(password)

        assert result >= 3


def test_evaluate_manual_strength_returns_integer_range():
    result = evaluate_manual_strength("password123")

    assert isinstance(result, int)
    assert 0 <= result <= 4
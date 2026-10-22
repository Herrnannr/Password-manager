import pytest

from password_manager.core.strength import (
    evaluate_entropy_score,
    evaluate_manual_strength,
)


@pytest.mark.parametrize(
    "number_entry, number_sale",
    [
        (0, 0),
        (3.25, 1),
        (31.6, 2),
        (59.8, 3),
        (122.68, 4)
    ]
)
def test_evaluate_entropy_score(number_entry, number_sale):
    result = evaluate_entropy_score(number_entry)
    assert result == number_sale


@pytest.mark.parametrize("proof_password",["12345678", "password"])
def test_evaluate_manual_strength_weak_password(proof_password):
    result = evaluate_manual_strength(proof_password)

    assert isinstance(result, int) 


@pytest.mark.parametrize("proof_password",["#Destr0._iac", "#!#AbHr1lc!77L0V3"])
def test_evaluate_manual_strength_strong_password(proof_password):
    result = evaluate_manual_strength(proof_password)

    assert result >= 3


def test_evaluate_manual_strength_returns_integer_range():
    result = evaluate_manual_strength("password123")

    assert isinstance(result, int) 
    assert 0 <= result <= 4
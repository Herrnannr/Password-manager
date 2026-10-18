import pytest

from password_manager.core.generator import (
    AMBIGUOUS,
    calculate_entropy,
    generate_password,
)


@pytest.mark.parametrize(
    "length, use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous, length_test",
    [
        (8, True, True, True, True, False, 8),
        (12, False, True, True, True, False, 12),
        (24, True, False, True, True, False, 24),
        (48, True, True, False, True, False, 48),
        (96, True, True, True, False, False, 96),
        (124, True, True, True, True, True, 124),
    ],
)
def test_generate_password_success(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    avoid_ambiguous: bool,
    length_test: int,
):
    result = generate_password(
        length, use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous
    )
    assert len(result) == length_test


@pytest.mark.parametrize("invalid_length", [2, 4, 129, 400])
def test_generate_password_invalid_length(invalid_length: int):
    with pytest.raises(ValueError):
        generate_password(length=invalid_length)


def test_generate_password_no_categories_selected():
    with pytest.raises(ValueError):
        generate_password(
            length=8,
            use_upper=False,
            use_lower=False,
            use_digits=False,
            use_symbols=False,
            avoid_ambiguous=False,
        )


def test_generate_password_avoid_ambiguous():
    # Ensures no ambiguous characters appear when the flag is enabled
    result = generate_password(length=64, avoid_ambiguous=True)
    assert not any(char in AMBIGUOUS for char in result)


@pytest.mark.parametrize(
    "length, use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous",
    [
        (8, True, True, True, True, False),
        (12, False, True, True, True, False),
        (24, True, False, True, True, False),
        (48, True, True, False, True, False),
        (96, True, True, True, False, False),
        (124, True, True, True, True, True),
    ],
)
def test_calculate_entropy_success(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    avoid_ambiguous: bool,
):
    result = calculate_entropy(
        length, use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous
    )
    assert isinstance(result, float)
    assert result > 0.0


@pytest.mark.parametrize("invalid_length", [0, -5, 2])
def test_calculate_entropy_invalid_length_returns_zero(invalid_length: int):
    # Entropy safely returns 0.0 instead of raising an error for UI compatibility
    result = calculate_entropy(length=invalid_length)
    assert result == 0.0


def test_calculate_entropy_no_categories_returns_zero():
    # Entropy safely returns 0.0 when all toggles are disabled
    result = calculate_entropy(
        length=8,
        use_upper=False,
        use_lower=False,
        use_digits=False,
        use_symbols=False,
        avoid_ambiguous=False,
    )
    assert result == 0.0

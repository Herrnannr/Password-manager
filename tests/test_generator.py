import math

import pytest

from password_manager.core.generator import (
    AMBIGUOUS,
    SYMBOLS,
    calculate_entropy,
    generate_password,
)


@pytest.mark.parametrize(
    "length, use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous",
    [
        (8, True, True, True, True, False),
        (12, False, True, True, True, False),
        (24, True, False, True, True, False),
        (48, True, True, False, True, False),
        (96, True, True, True, False, False),
        (128, True, True, True, True, True),
    ],
)
def test_generate_password_success(
    length,
    use_upper,
    use_lower,
    use_digits,
    use_symbols,
    avoid_ambiguous,
):
    result = generate_password(
        length, use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous
    )
    assert len(result) == length


@pytest.mark.parametrize(
    "invalid_length, error_match",
    [
        (0, "at least"),
        (4, "at least"),
        (7, "at least"),
        (129, "maximum"),
        (400, "maximum"),
    ],
)
def test_generate_password_invalid_length(invalid_length, error_match):
    with pytest.raises(ValueError, match=error_match):
        generate_password(length=invalid_length)


def test_generate_password_no_categories_selected():
    with pytest.raises(ValueError, match="parameter must be selected"):
        generate_password(
            length=8,
            use_upper=False,
            use_lower=False,
            use_digits=False,
            use_symbols=False,
            avoid_ambiguous=False,
        )


def test_always_includes_every_active_category():
    for _ in range(1000):
        result = generate_password(
            8, use_upper=True, use_lower=True, use_digits=True, use_symbols=True
        )
        assert any(c.isupper() for c in result)
        assert any(c.islower() for c in result)
        assert any(c.isdigit() for c in result)
        assert any(c in SYMBOLS for c in result)


def test_disabled_categories_never_appear():
    for _ in range(200):
        res_no_sym = generate_password(16, use_symbols=False)
        assert not any(c in SYMBOLS for c in res_no_sym)

        res_no_dig = generate_password(16, use_digits=False)
        assert not any(c.isdigit() for c in res_no_dig)

        res_no_up = generate_password(16, use_upper=False)
        assert not any(c.isupper() for c in res_no_up)

        res_no_low = generate_password(16, use_lower=False)
        assert not any(c.islower() for c in res_no_low)


def test_avoid_ambiguous_comprehensive():
    for _ in range(500):
        result = generate_password(64, avoid_ambiguous=True)
        assert not any(char in AMBIGUOUS for char in result)

        result_digits = generate_password(
            32,
            use_upper=False,
            use_lower=False,
            use_digits=True,
            use_symbols=False,
            avoid_ambiguous=True,
        )
        assert not any(char in AMBIGUOUS for char in result_digits)
        assert all(c in "23456789" for c in result_digits)


@pytest.mark.parametrize(
    "length, use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous",
    [
        (8, True, True, True, True, False),
        (12, False, True, True, True, False),
        (24, True, False, True, True, False),
        (48, True, True, False, True, False),
        (96, True, True, True, False, False),
        (128, True, True, True, True, True),
    ],
)
def test_calculate_entropy_success(
    length,
    use_upper,
    use_lower,
    use_digits,
    use_symbols,
    avoid_ambiguous,
):
    result = calculate_entropy(
        length, use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous
    )
    assert isinstance(result, float)
    assert result > 0.0


def test_calculate_entropy_concrete_values():
    entropy = calculate_entropy(
        length=10,
        use_upper=False,
        use_lower=False,
        use_digits=True,
        use_symbols=False,
        avoid_ambiguous=False,
    )

    expected = 10 * math.log2(10)
    assert entropy == pytest.approx(expected)

    entropy_normal = calculate_entropy(
        16,
        use_digits=True,
        use_symbols=False,
        use_lower=False,
        use_upper=False,
        avoid_ambiguous=False,
    )
    entropy_filtered = calculate_entropy(
        16,
        use_digits=True,
        use_symbols=False,
        use_lower=False,
        use_upper=False,
        avoid_ambiguous=True,
    )
    assert entropy_filtered < entropy_normal


@pytest.mark.parametrize("invalid_length", [0, -1, -5])
def test_calculate_entropy_invalid_length_returns_zero(invalid_length: int):
    result = calculate_entropy(length=invalid_length)
    assert result == 0.0


def test_calculate_entropy_no_categories_returns_zero():
    result = calculate_entropy(
        length=8,
        use_upper=False,
        use_lower=False,
        use_digits=False,
        use_symbols=False,
        avoid_ambiguous=False,
    )
    assert result == 0.0

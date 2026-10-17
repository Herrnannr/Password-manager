import secrets
import string


def generar_contraseña(
    length: int,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:

    if length < 8:
        raise ValueError("The password must be at least 8 characters long.")

    if length > 128:
        raise ValueError("The password must have a maximum of 128 characters.")

    symbols = "!¡@#$%&/()=¿?|+-{}<>,.;:"

    char_pools = [
        (use_upper, string.ascii_uppercase),
        (use_lower, string.ascii_lowercase),
        (use_digits, string.digits),
        (use_symbols, symbols),
    ]
    characters = "".join(chars for enabled, chars in char_pools if enabled)

    if not characters:
        raise ValueError("At least one parameter must be selected.")

    password = [secrets.choice(characters) for _ in range(length)]

    return "".join(password)

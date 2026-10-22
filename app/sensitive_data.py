from __future__ import annotations

import json
import re

# A sensitive name may carry an application/provider prefix (`my_secret`,
# `oauth_client_secret`, `db_password`, `client__secret`): the keyword only needs
# to start at a token boundary, i.e. not be preceded by a letter or digit. It
# must still be the whole final word of the name (a `:`/`=` must follow it), so
# `secretary`, `secrets_count`, `client_id` and `client_name` are not matched.
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:aws[_ -]?)?(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|passwd|"
    r"client[_ -]?secret|secret(?:[_ -]?(?:access[_ -]?key|key|token))?|private[_ -]?key|seed(?:\s+phrase)?|"
    r"mnemonic)\s*['\"]?\s*[:=]\s*\S+"
)
# camelCase names (`dbPassword`, `oauthClientSecret`): case-sensitive on purpose.
# The keyword must start with an uppercase letter right after a lowercase letter
# or digit, and be the final word of the name, so `secretary` or `secretsCount`
# do not match.
CAMEL_CASE_SECRET_PATTERN = re.compile(
    r"(?<=[a-z0-9])(?:ApiKey|AccessToken|RefreshToken|Password|Passwd|ClientSecret|"
    r"Secret(?:AccessKey|Key|Token)?|PrivateKey|SeedPhrase|Mnemonic)"
    r"\s*['\"]?\s*[:=]\s*\S+"
)
PRIVATE_KEY_PATTERN = re.compile(r"(?i)\b0x[0-9a-f]{64}\b")
SHA256_FIELD_PATTERN = re.compile(r"(?i)(?:^|_)sha256$")
SHA256_VALUE_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z", re.IGNORECASE)
PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
)
TOKEN_PATTERN = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16})\b"
)
AUTHORIZATION_PATTERN = re.compile(
    r"(?i)\bauthorization\b\s*[:=]\s*[A-Za-z][A-Za-z0-9_-]*\s+\S+"
)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)
UNICODE_ESCAPE_PATTERN = re.compile(r"\\u[0-9a-fA-F]{4}")
REDACTED_SENSITIVE_CONTENT = "[contenido omitido: patrón sensible reconocido]"
REDACTED_INVALID_JSON_CONTENT = "[contenido omitido: JSON no válido]"


class DuplicateJSONKeyError(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJSONKeyError from None
        value[key] = item
    return value


def _loads_json_without_duplicate_keys(value: str) -> object:
    return json.loads(value, object_pairs_hook=_object_without_duplicate_keys)


def _looks_like_json(value: str) -> bool:
    return value.lstrip("\ufeff").lstrip().startswith(("{", "[", '"'))


def contains_duplicate_json_keys(value: str) -> bool:
    try:
        _loads_json_without_duplicate_keys(value)
    except DuplicateJSONKeyError:
        return True
    except json.JSONDecodeError:
        return False
    except RecursionError:
        return True
    return False


def contains_sensitive_content(value: str) -> bool:
    return contains_sensitive_content_in_value(value)


def _quoted_candidates(value: str, start: int):
    # Single linear pass (no regex backtracking). Yields (text, terminated, is_key)
    # for each double-quoted run; a backslash always consumes the next character.
    length = len(value)
    opening = value.find('"', start)
    while opening != -1:
        index = opening + 1
        while index < length and value[index] not in '"\n':
            index += 2 if value[index] == "\\" else 1
        if index >= length or value[index] == "\n":
            yield value[opening:index], False, False
            opening = value.find('"', index + 1) if index < length else -1
            continue
        after = index + 1
        while after < length and value[after] in " \t\r":
            after += 1
        yield value[opening : index + 1], True, after < length and value[after] == ":"
        opening = value.find('"', index + 1)


def _has_sensitive_escaped_key(value: str) -> bool:
    # Quoted keys containing backslash escapes are decoded before applying the same
    # name policy as plain keys. Keys that cannot be decoded, and unterminated
    # quoted runs with a Unicode escape, cannot be verified and fail closed.
    # Quotes are paired from both parities so one stray quote cannot hide a key.
    if "\\" not in value:
        return False
    first_quote = value.find('"')
    if first_quote == -1:
        return False
    for start in (0, first_quote + 1):
        for text, terminated, is_key in _quoted_candidates(value, start):
            if "\\" not in text:
                continue
            if not terminated:
                if UNICODE_ESCAPE_PATTERN.search(text):
                    return True
                continue
            if not is_key:
                continue
            try:
                decoded = json.loads(text)
            except ValueError:
                return True
            candidate = f"{decoded}=x"
            if SECRET_ASSIGNMENT_PATTERN.search(candidate) or CAMEL_CASE_SECRET_PATTERN.search(
                candidate
            ):
                return True
    return False


def _matches_sensitive_pattern(value: str) -> bool:
    return _has_sensitive_escaped_key(value) or any(
        pattern.search(value)
        for pattern in (
            SECRET_ASSIGNMENT_PATTERN,
            CAMEL_CASE_SECRET_PATTERN,
            PRIVATE_KEY_PATTERN,
            PEM_PRIVATE_KEY_PATTERN,
            TOKEN_PATTERN,
            AUTHORIZATION_PATTERN,
            JWT_PATTERN,
        )
    )


def _is_sensitive_field(key: object) -> bool:
    if not isinstance(key, str):
        return False
    return contains_sensitive_content(f"{key}=synthetic-value") or contains_sensitive_content(
        f"{key}=Bearer synthetic-value"
    )


def _is_sha256_field(key: object, value: object) -> bool:
    return (
        isinstance(key, str)
        and SHA256_FIELD_PATTERN.search(key) is not None
        and isinstance(value, str)
        and SHA256_VALUE_PATTERN.fullmatch(value) is not None
    )


def _has_value(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        return bool(value)
    return True


def contains_sensitive_content_in_value(value: object) -> bool:
    pending = [value]
    visited_containers: set[int] = set()
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            if _looks_like_json(current):
                try:
                    parsed = _loads_json_without_duplicate_keys(current)
                except DuplicateJSONKeyError:
                    return True
                except json.JSONDecodeError:
                    pass
                except RecursionError:
                    return True
                else:
                    pending.append(parsed)
                    continue
            if _matches_sensitive_pattern(current):
                return True
        elif isinstance(current, dict):
            identity = id(current)
            if identity not in visited_containers:
                visited_containers.add(identity)
                for key, item in current.items():
                    if _is_sha256_field(key, item):
                        if isinstance(key, str) and _matches_sensitive_pattern(key):
                            return True
                        continue
                    if _is_sensitive_field(key) and _has_value(item):
                        return True
                    if (
                        isinstance(key, str)
                        and isinstance(item, str)
                        and _matches_sensitive_pattern(f"{key}: {item}")
                    ):
                        return True
                pending.extend(current.keys())
                pending.extend(current.values())
        elif isinstance(current, (list, tuple, set, frozenset)):
            identity = id(current)
            if identity not in visited_containers:
                visited_containers.add(identity)
                pending.extend(current)
    return False


def redact_sensitive_content_in_value(value: object) -> object:
    try:
        return _redact_sensitive_value(value)
    except RecursionError:
        if contains_sensitive_content_in_value(value):
            return REDACTED_SENSITIVE_CONTENT
        return value


def _redact_sensitive_value(value: object) -> object:
    if isinstance(value, str):
        if _looks_like_json(value):
            try:
                parsed = _loads_json_without_duplicate_keys(value)
            except RecursionError:
                return REDACTED_SENSITIVE_CONTENT
            except DuplicateJSONKeyError:
                return REDACTED_SENSITIVE_CONTENT
            except json.JSONDecodeError:
                return REDACTED_INVALID_JSON_CONTENT
            if not isinstance(parsed, str) or parsed != value:
                if contains_sensitive_content_in_value(parsed):
                    try:
                        redacted = _redact_sensitive_value(parsed)
                        return json.dumps(
                            redacted,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                    except (TypeError, ValueError, RecursionError):
                        return REDACTED_SENSITIVE_CONTENT
                return value
        return REDACTED_SENSITIVE_CONTENT if _matches_sensitive_pattern(value) else value
    if isinstance(value, dict):
        redacted: dict[object, object] = {}
        for key, item in value.items():
            if isinstance(key, str) and (
                _matches_sensitive_pattern(key) or _is_sensitive_field(key)
            ):
                redacted[REDACTED_SENSITIVE_CONTENT] = (
                    REDACTED_SENSITIVE_CONTENT if _has_value(item) else item
                )
            elif _is_sha256_field(key, item):
                redacted_key = (
                    REDACTED_SENSITIVE_CONTENT
                    if isinstance(key, str) and _matches_sensitive_pattern(key)
                    else key
                )
                redacted[redacted_key] = item
            elif _is_sensitive_field(key) and _has_value(item):
                redacted[key] = REDACTED_SENSITIVE_CONTENT
            else:
                redacted_key = (
                    REDACTED_SENSITIVE_CONTENT
                    if isinstance(key, str) and _matches_sensitive_pattern(key)
                    else key
                )
                redacted[redacted_key] = _redact_sensitive_value(item)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_sensitive_value(item) for item in value)
    if isinstance(value, set):
        return {_redact_sensitive_value(item) for item in value}
    if isinstance(value, frozenset):
        return frozenset(_redact_sensitive_value(item) for item in value)
    return value

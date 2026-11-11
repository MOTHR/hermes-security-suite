"""Test seam for the v1.9.0 contract migration.

``pre_llm_call`` no longer returns ``{"user_message": ...}`` — the sanitized
prompt is staged for the ``llm_request`` middleware (upstream contract). The
pipeline itself is unchanged; these helpers let legacy pipeline tests read
the staged result without re-asserting the removed return shape.

Legacy adapter: returns a dict shaped like the old return value so existing
assertions (``result["user_message"]``) keep working against the STAGED
sanitized text. Veto results are returned unchanged.
"""

from __future__ import annotations


def staged_result(plugin, result):
    """Wrap a pre_llm_call return for legacy assertions.

    None + staged mask  -> {"user_message": <sanitized>} (old shape)
    Veto dict           -> returned unchanged ({'action': 'block', ...})
    None + nothing staged -> None (bypassed/clean prompt)
    """
    if result is not None:
        return result
    shields = getattr(plugin, "_staged_shields", {})
    if not shields:
        return None
    # Legacy callers stage exactly one turn; the newest entry is theirs.
    staged = next(reversed(shields))
    entry = shields[staged]
    if entry is None:
        return None
    return {"user_message": entry["sanitized"]}

"""Tests for Voice Engine voice-turn interaction policy."""

from voice_engine import (
    VoiceSurface,
    build_permission_prompt,
    build_turn_start_confirmation,
    concise_heard_text,
)


def test_turn_start_confirmation_repeats_user_request_before_work():
    confirmation = build_turn_start_confirmation(
        "Sifrot, add the ACPX stuff to the repo and run the tests",
        assistant_names=("Sifrot", "Cipri"),
    )

    assert confirmation is not None
    assert confirmation.surface == VoiceSurface.VOICE_CHANNEL
    assert confirmation.heard_text == "add the ACPX stuff to the repo and run the tests"
    assert confirmation.spoken_text.startswith("I heard you.")
    assert "You asked me to add the ACPX stuff" in confirmation.spoken_text
    assert confirmation.spoken_text.endswith("I’ll work on that now.")


def test_turn_start_confirmation_sanitizes_and_truncates_machine_text():
    heard = concise_heard_text(
        "Cypherot, inspect `/home/lock/.hermes/config.yaml` and https://example.com/abc "
        + "very long " * 50,
        assistant_names=("Cypherot",),
        max_chars=90,
    )

    assert "a file path" in heard
    assert "a link" in heard
    assert "/home/lock" not in heard
    assert "https://" not in heard
    assert heard.endswith("…")
    assert len(heard) <= 91


def test_turn_start_confirmation_returns_none_for_empty_transcript():
    assert build_turn_start_confirmation("   ") is None


def test_permission_prompt_is_spoken_in_voice_and_shown_in_text():
    prompt = build_permission_prompt(
        "restart the Hermes gateway",
        reason="new voice settings only load after restart",
        risk="brief Discord and Telegram interruption",
        targets=("Discord voice adapter", "Telegram gateway"),
        request_id="abc123",
    )

    assert prompt.surface == VoiceSurface.BOTH
    assert prompt.approval_options == ("approve", "deny")
    assert prompt.spoken_text.startswith("I need your permission to restart the Hermes gateway")
    assert "This touches Discord voice adapter and Telegram gateway" in prompt.spoken_text
    assert "Risk: brief Discord and Telegram interruption" in prompt.spoken_text
    assert "Please approve or deny it in chat" in prompt.spoken_text
    assert "Permission needed: restart the Hermes gateway." in prompt.text_text
    assert "Request ID: abc123." in prompt.text_text


def test_permission_prompt_sanitizes_targets_for_speech():
    prompt = build_permission_prompt(
        "write files",
        targets=("/home/lock/.hermes/config.yaml", "https://example.com"),
    )

    assert "a file path" in prompt.spoken_text
    assert "a link" in prompt.spoken_text
    assert "/home/lock" not in prompt.spoken_text
    assert "https://" not in prompt.spoken_text

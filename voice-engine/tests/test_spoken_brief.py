"""Tests for Voice Engine spoken-brief behavior."""

from voice_engine import sanitize_for_speech, spoken_brief, transform_tts_text


def test_sanitize_replaces_machine_tokens_with_speakable_labels():
    text = (
        "Updated `/home/lock/.hermes/config.yaml` and see "
        "https://example.com/a/b?token=abc plus sha 0123456789abcdef0123456789abcdef."
    )

    spoken = sanitize_for_speech(text)

    assert "a file path" in spoken
    assert "a link" in spoken
    assert "a hash" in spoken
    assert "/home/lock" not in spoken
    assert "https://" not in spoken
    assert "0123456789abcdef" not in spoken


def test_long_technical_response_becomes_short_brief_with_text_fallback_notice():
    response = "\n".join(
        [
            "Done: I implemented the gateway voice middleware hook.",
            "Root cause: the TTS path reused the full text response, including logs and paths.",
            "```python\nprint('/tmp/hermes/example')\n```",
            "Details: " + "x " * 500,
        ]
    )

    brief = spoken_brief(response)

    assert brief.startswith("Done")
    assert "Root cause" in brief
    assert "full details in text" in brief
    assert "```" not in brief
    assert len(brief) < 430


def test_short_clean_response_passes_through():
    assert spoken_brief("Done — that sample is ready to audition.") == "Done — that sample is ready to audition."


def test_transform_tts_text_returns_none_for_empty_input():
    assert transform_tts_text(response_text="") is None

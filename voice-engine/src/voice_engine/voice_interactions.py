"""Voice interaction policy helpers.

These helpers define the spoken UX around a voice-originated turn:

1. Confirm what the user said at the beginning of the turn.
2. Surface approval/authorization requests in the voice channel instead of
   silently waiting on a text-only prompt.
3. Keep final summaries separate from the up-front acknowledgement.

The module is deterministic and local-only.  It does not synthesize or play
speech itself; host adapters call these helpers and route the returned text to
whatever local TTS/voice-channel path they already use.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence

from .spoken_brief import sanitize_for_speech


class VoiceSurface(str, Enum):
    """Where a voice interaction should be surfaced."""

    VOICE_CHANNEL = "voice_channel"
    TEXT_CHAT = "text_chat"
    BOTH = "both"


@dataclass(frozen=True)
class TurnStartConfirmation:
    """A short spoken acknowledgement for a voice-originated user turn."""

    spoken_text: str
    heard_text: str
    surface: VoiceSurface = VoiceSurface.VOICE_CHANNEL


@dataclass(frozen=True)
class PermissionPrompt:
    """A permission request that should be spoken in voice and shown in text."""

    spoken_text: str
    text_text: str
    action: str
    risk: str = ""
    approval_options: tuple[str, ...] = ("approve", "deny")
    surface: VoiceSurface = VoiceSurface.BOTH
    metadata: dict[str, str] = field(default_factory=dict)


_FILLER_PREFIXES = (
    "um",
    "uh",
    "hey",
    "okay",
    "ok",
    "so",
)


def _collapse_spaces(text: str) -> str:
    return " ".join(str(text or "").split())


def _strip_addressing(text: str, assistant_names: Sequence[str] = ()) -> str:
    heard = _collapse_spaces(text)
    if not heard:
        return ""
    lowered = heard.lower()
    names = [n.lower().strip(" ,.:;!?-") for n in assistant_names if n]
    for name in names:
        for prefix in (name, f"{name},", f"{name}:"):
            if lowered.startswith(prefix):
                return heard[len(prefix):].lstrip(" ,.:;!?-")
    return heard


def concise_heard_text(
    transcript: str,
    *,
    assistant_names: Sequence[str] = (),
    max_chars: int = 180,
) -> str:
    """Return a concise, speakable version of what STT heard.

    This is meant for the beginning of the turn: "I heard you ask me to …".
    It strips the wake/address name, sanitizes machine tokens, and truncates
    without pretending to understand more than the transcript contains.
    """

    heard = _strip_addressing(transcript, assistant_names)
    heard = sanitize_for_speech(heard)
    heard = _collapse_spaces(heard).strip(" ,")
    words = heard.split()
    while words and words[0].lower().strip(" ,.:;!?-") in _FILLER_PREFIXES:
        words.pop(0)
    heard = " ".join(words)
    if len(heard) <= max_chars:
        return heard
    cut = heard[:max_chars].rsplit(" ", 1)[0].rstrip(" ,;:")
    return cut + "…"


def build_turn_start_confirmation(
    transcript: str,
    *,
    assistant_names: Sequence[str] = (),
    prefix: str = "I heard you.",
    max_heard_chars: int = 180,
) -> TurnStartConfirmation | None:
    """Build a short spoken confirmation for a voice-originated turn.

    Returns ``None`` when there is no useful transcript.  Host integrations
    should play this immediately before doing longer tool work, then later speak
    the normal final summary.
    """

    heard = concise_heard_text(
        transcript,
        assistant_names=assistant_names,
        max_chars=max_heard_chars,
    )
    if not heard:
        return None
    spoken = f"{prefix} You asked me to {heard}. I’ll work on that now."
    return TurnStartConfirmation(spoken_text=spoken, heard_text=heard)


def _join_items(items: Iterable[str], *, limit: int = 3) -> str:
    clean = [sanitize_for_speech(x).strip(" .") for x in items if str(x or "").strip()]
    clean = [x for x in clean if x]
    if not clean:
        return ""
    shown = clean[:limit]
    if len(clean) > limit:
        shown.append(f"{len(clean) - limit} more item{'s' if len(clean) - limit != 1 else ''}")
    if len(shown) == 1:
        return shown[0]
    if len(shown) == 2:
        return f"{shown[0]} and {shown[1]}"
    return ", ".join(shown[:-1]) + ", and " + shown[-1]


def build_permission_prompt(
    action: str,
    *,
    reason: str = "",
    risk: str = "",
    targets: Sequence[str] = (),
    approval_options: Sequence[str] = ("approve", "deny"),
    request_id: str | None = None,
) -> PermissionPrompt:
    """Build a prompt that should be spoken in VC and shown in text.

    Use this whenever an operation is waiting on user authorization: installs,
    service restarts, config writes, destructive commands, publishes, or any
    other significant side effect.  The spoken form is intentionally short; the
    text form keeps a little more detail.
    """

    clean_action = sanitize_for_speech(action).strip(" .") or "take an action"
    clean_reason = sanitize_for_speech(reason).strip(" .")
    clean_risk = sanitize_for_speech(risk).strip(" .")
    target_text = _join_items(targets)

    spoken_bits = [f"I need your permission to {clean_action}"]
    if target_text:
        spoken_bits.append(f"This touches {target_text}")
    if clean_risk:
        spoken_bits.append(f"Risk: {clean_risk}")
    spoken_bits.append("Please approve or deny it in chat")
    spoken = ". ".join(spoken_bits) + "."

    text_lines = [f"Permission needed: {clean_action}."]
    if clean_reason:
        text_lines.append(f"Reason: {clean_reason}.")
    if target_text:
        text_lines.append(f"Targets: {target_text}.")
    if clean_risk:
        text_lines.append(f"Risk: {clean_risk}.")
    if request_id:
        text_lines.append(f"Request ID: {request_id}.")
    text_lines.append("Reply with approve or deny.")

    return PermissionPrompt(
        spoken_text=spoken,
        text_text="\n".join(text_lines),
        action=clean_action,
        risk=clean_risk,
        approval_options=tuple(approval_options),
        metadata={"request_id": request_id or ""},
    )

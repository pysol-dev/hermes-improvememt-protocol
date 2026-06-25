# voice-engine

`voice-engine` is a local-first voice middleware package for Hermes Agent.

The first slices implement deterministic spoken briefs and voice-turn interaction policy:

- keep the full assistant answer in text,
- speak a short version in Discord/Telegram voice,
- replace paths, URLs, hashes, UUIDs, code blocks, and config keys with speakable labels,
- preserve useful status fields such as `Done`, `Root cause`, `Next step`, `Blocked`, and `Risk`,
- confirm what the user said at the beginning of a voice-originated turn,
- surface authorization/permission prompts in voice chat as well as text chat,
- avoid a slow summarizer/model call on the hot path.

## Hermes hook

This package is intended to plug into Hermes via a `transform_tts_text` hook:

```python
def register(ctx):
    ctx.register_hook("transform_tts_text", transform_tts_text)
```

That hook changes only the text sent to TTS. It does not alter the written assistant response.

## Voice-turn confirmations

For voice-originated turns, call `build_turn_start_confirmation()` as soon as STT has a usable transcript and before long-running tool work starts:

```python
from voice_engine import build_turn_start_confirmation

confirmation = build_turn_start_confirmation(
    transcript,
    assistant_names=("Sifrot", "Cipri", "Cypherot"),
)
if confirmation:
    await play_in_voice_channel(confirmation.spoken_text)
```

The final answer should still use the normal summary path after work completes. This creates the conversational shape: acknowledge what was heard, do the work, then return with the outcome.

## Spoken authorization prompts

When Hermes is waiting for approval, call `build_permission_prompt()` and route `spoken_text` to the active voice channel while keeping `text_text` in chat for buttons or explicit approve/deny replies:

```python
from voice_engine import build_permission_prompt

prompt = build_permission_prompt(
    "restart the Hermes gateway",
    reason="new voice settings only load after restart",
    risk="brief Discord and Telegram interruption",
    targets=("Discord voice adapter", "Telegram gateway"),
)
await play_in_voice_channel(prompt.spoken_text)
await send_chat_message(prompt.text_text)
```

This prevents approval prompts from silently appearing only in text while the user is interacting by voice.

## Development

```bash
cd voice-engine
python -m pytest -q
```

## Status

Prototype extracted from live Hermes Discord voice work. The current implementation is deterministic and local-only.

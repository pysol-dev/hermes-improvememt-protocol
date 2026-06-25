# voice-engine

`voice-engine` is a local-first voice middleware package for Hermes Agent.

The first slice implements deterministic spoken briefs for automatic TTS replies:

- keep the full assistant answer in text,
- speak a short version in Discord/Telegram voice,
- replace paths, URLs, hashes, UUIDs, code blocks, and config keys with speakable labels,
- preserve useful status fields such as `Done`, `Root cause`, `Next step`, `Blocked`, and `Risk`,
- avoid a slow summarizer/model call on the hot path.

## Hermes hook

This package is intended to plug into Hermes via a `transform_tts_text` hook:

```python
def register(ctx):
    ctx.register_hook("transform_tts_text", transform_tts_text)
```

That hook changes only the text sent to TTS. It does not alter the written assistant response.

## Development

```bash
cd voice-engine
python -m pytest -q
```

## Status

Prototype extracted from live Hermes Discord voice work. The current implementation is deterministic and local-only.

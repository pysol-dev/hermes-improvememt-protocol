"""Hermes plugin adapter for Voice Engine.

Install/register this with Hermes as a plugin hook provider. It listens for
``transform_tts_text`` and returns a shortened/sanitized spoken version while
leaving the full written assistant response unchanged.
"""

from __future__ import annotations

from .spoken_brief import transform_tts_text


def register(ctx):
    ctx.register_hook("transform_tts_text", transform_tts_text)

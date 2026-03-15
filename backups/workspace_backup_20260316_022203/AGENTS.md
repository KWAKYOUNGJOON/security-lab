## Skills
A skill is a set of local instructions to follow that is stored in a `SKILL.md` file. Below is the list of skills that can be used. Each entry includes a name, description, and file path so you can open the source for full instructions when using a specific skill.
### Available skills
- openai-docs: Use when the user asks how to build with OpenAI products or APIs and needs up-to-date official documentation with citations, help choosing the latest model for a use case, or explicit GPT-5.4 upgrade and prompt-upgrade guidance; prioritize OpenAI docs MCP tools, use bundled references only as helper context, and restrict any fallback browsing to official OpenAI domains. (file: C:/Users/kyj/.codex/skills/.system/openai-docs/SKILL.md)
- skill-creator: Guide for creating effective skills. This skill should be used when users want to create a new skill (or update an existing skill) that extends Codex's capabilities with specialized knowledge, workflows, or tool integrations. (file: C:/Users/kyj/.codex/skills/.system/skill-creator/SKILL.md)
- skill-installer: Install Codex skills into $CODEX_HOME/skills from a curated list or a GitHub repo path. Use when a user asks to list installable skills, install a curated skill, or install a skill from another repo (including private repos). (file: C:/Users/kyj/.codex/skills/.system/skill-installer/SKILL.md)
### How to use skills
- Discovery: The list above is the skills available in this session (name + description + file path). Skill bodies live on disk at the listed paths.
- Trigger rules: If the user names a skill (with `$SkillName` or plain text) OR the task clearly matches a skill's description shown above, you must use that skill for that turn. Multiple mentions mean use them all. Do not carry skills across turns unless re-mentioned.
- Missing/blocked: If a named skill isn't in the list or the path can't be read, say so briefly and continue with the best fallback.
- How to use a skill (progressive disclosure):
  1) After deciding to use a skill, open its `SKILL.md`. Read only enough to follow the workflow.
  2) When `SKILL.md` references relative paths (e.g., `scripts/foo.py`), resolve them relative to the skill directory listed above first, and only consider other paths if needed.
  3) If `SKILL.md` points to extra folders such as `references/`, load only the specific files needed for the request; don't bulk-load everything.
  4) If `scripts/` exist, prefer running or patching them instead of retyping large code blocks.
  5) If `assets/` or templates exist, reuse them instead of recreating from scratch.
- Coordination and sequencing:
  - If multiple skills apply, choose the minimal set that covers the request and state the order you'll use them.
  - Announce which skill(s) you're using and why (one short line). If you skip an obvious skill, say why.
- Context hygiene:
  - Keep context small: summarize long sections instead of pasting them; only load extra files when needed.
  - Avoid deep reference-chasing: prefer opening only files directly linked from `SKILL.md` unless you're blocked.
  - When variants exist (frameworks, providers, domains), pick only the relevant reference file(s) and note that choice.
- Safety and fallback: If a skill can't be applied cleanly (missing files, unclear instructions), state the issue, pick the next-best approach, and continue.

## Python Secure Coding Rules For This Project
- All Python changes in this workspace must follow secure coding principles by default, not as optional cleanup after implementation.
- Treat every scanner artifact, XML/JSON/JSONL record, manual note, override file, and CLI argument as untrusted input.
- Prefer allowlists over denylists for file extensions, schema fields, template names, output targets, and package contents.
- Validate input size, structure, encoding, and required fields before parsing. Fail closed for unsafe or ambiguous input.
- Do not trust path input. Resolve paths with `Path.resolve()`, verify they stay under the intended workspace root, and reject symlinks or path traversal when reading or packaging files.
- Avoid unsafe parsing and execution patterns such as `eval`, `exec`, dynamic imports from user input, `pickle`, unsafe deserialization, and unsandboxed template loading from untrusted locations.
- When handling XML, use safe parsing practices and add defensive limits against oversized or malformed documents that could trigger denial of service.
- When handling JSONL or large artifacts, process incrementally where possible and enforce explicit size limits, timeouts, or record count limits to reduce memory exhaustion risk.
- Never expose raw request/response bodies, tokens, cookies, authorization headers, session identifiers, PII, or internal decision traces in customer-facing outputs.
- Apply redaction before persistence or export whenever feasible, and verify packaging logic excludes raw artifacts from customer bundles.
- Escape or neutralize untrusted content before rendering Markdown, HTML-like content, CSV, DOCX, or presentation data. In particular, guard against Markdown/HTML injection and CSV formula injection.
- Keep Jinja2 templates, document templates, mappings, and scoring rules developer-controlled. If template selection is configurable, restrict it to approved local templates only.
- Use `yaml.safe_load` and equivalent safe loaders only. Reject malformed override, suppression, or review files rather than guessing.
- Preserve auditability for manual promotions, suppressions, and severity overrides. Security-relevant changes must leave traceable logs or review artifacts.
- Use least-privilege file operations: create only the files needed for the run, avoid overwriting unrelated files, and prefer atomic writes for reports, overrides, and manifests.
- Do not log secrets or full raw evidence unless the destination is explicitly internal-only and documented.
- Add or update tests for security-sensitive behavior when touching parsers, redaction, packaging, report rendering, override handling, or path validation.
- If a requested implementation conflicts with these secure coding rules, explicitly call out the conflict and choose the safer design unless the user directs otherwise with full context.

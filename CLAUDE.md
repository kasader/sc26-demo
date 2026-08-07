# CLAUDE.md

## Bilingual documents must stay in lockstep

Some docs in this repo exist in both English and Japanese. These pairs are
translations of one another, not independent documents:

| English (source) | Japanese |
| --- | --- |
| `sec-camp/guard/DEMO_GUIDE.md` | `sec-camp/guard/DEMO_GUIDE.jp.md` |
| `sec-camp/README.en.md` | `sec-camp/README.md` |

Rules:

- **Never edit one without editing the other in the same change.** If you change
  a section, a number, a command, or a speaker line in one file, make the
  equivalent change in its counterpart before finishing.
- **English is the source of truth.** Author new content in English first, then
  translate. If the two have drifted, reconcile toward the English unless the
  user says otherwise.
- **Keep the structure identical** — same section numbering, same headings in
  the same order, same tables with the same rows. A reader should be able to
  follow either file and land on the same `§N` at the same moment.
- **Do not translate** code blocks, shell commands, flag names, counter names
  (`total` / `passed` / `dropped-rate` / `dropped-protocol`), map names, or
  identifiers from the source. Translate prose and the `[...]` stage directions.
- Each file links to its counterpart at the top. Preserve those links.

`DEMO_GUIDE.md` in particular is a **spoken script** for a live presentation:
`>` lines are read aloud, `[...]` lines are stage directions. Keep the Japanese
natural to *speak*, not literally faithful — matching meaning and timing beats
matching sentence structure.

## Demo facts worth not breaking

The script quotes concrete numbers that come from the code. If you change these,
update both guides:

- `attacker/main.go` modes: `legit` 3×2 pps, `garbage` 2×10, `flood` 2×150,
  `evasive` 50×5.
- Guard defaults: `-rate 30` (pps per source), `-block-ttl 15s`, target
  `10.10.0.2:9999`.

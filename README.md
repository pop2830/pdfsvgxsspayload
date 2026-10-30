# pdfsvgxsspayload

PDF / SVG XSS payload collection for authorized security research.

All payloads below execute `app.alert("XSS")` on document / page open and are
designed to probe upload filters that do byte / signature scanning or reject
mark-of-the-web (MOTW) files. Each file varies the evasion technique so you can
bisect exactly which signature a target filter matches.

- `v1_noflags.pdf` — **baseline / control**. Pristine `/OpenAction` with a
  plaintext `app.alert("XSS")` stream. No compression, no base64, no keyword
  splitting. Confirms the plain (non-evaded) payload is detected — everything
  else is compared against this.
- `poc-bracket.pdf` — **bracket-notation access**. `app["alert"]("XSS")` avoids
  the literal `app.alert` token; triggered via the page **Additional-Action
  open** (`/AA /O`) instead of `/OpenAction`.
- `poc-charcode.pdf` — **runtime char-code build**. `app[String.fromCharCode(...)]("XSS")`
  builds the `alert` name at runtime so no literal `alert` string exists in the
  file; also triggered via page open `/AA /O`.
- `v2_compress_only.pdf` — **compressed-stream** variant: JS wrapped in
  `eval(atob(...))` and embedded in a `/Filter /FlateDecode` stream, so a
  plaintext scanner never sees the script at all.
- `bypass_pdfxss.pdf` — **max-evasion** (output of `gen_pdfxss_bypass.py`, all
  layers on): compressed `FlateDecode` stream + `eval(atob(...))` + `/JavaScript`
  and `/OpenAction` keywords split with `%` line-comments (e.g. `Java%_Script`).

## Download

| Payload | Direct link |
| --- | --- |
| `v1_noflags.pdf` | https://pop2830.github.io/pdfsvgxsspayload/v1_noflags.pdf |
| `poc-bracket.pdf` | https://pop2830.github.io/pdfsvgxsspayload/poc-bracket.pdf |
| `poc-charcode.pdf` | https://pop2830.github.io/pdfsvgxsspayload/poc-charcode.pdf |
| `v2_compress_only.pdf` | https://pop2830.github.io/pdfsvgxsspayload/v2_compress_only.pdf |
| `bypass_pdfxss.pdf` | https://pop2830.github.io/pdfsvgxsspayload/bypass_pdfxss.pdf |

## Generator

`gen_pdfxss_bypass.py` builds the evasion payloads and each defense layer is
independently removable (`--no-compress --no-base64 --no-split`) so you can
find the minimum combination that trips a given filter. Run
`python gen_pdfxss_bypass.py -o out.pdf` (optionally `--text='app.alert("XSS")'`).
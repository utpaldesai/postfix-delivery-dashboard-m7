from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")

assert "function spamRuleRows(distribution)" in main
assert 'class="qscore-hover"' in main
assert 'class="qscore-tooltip"' in main
assert 'class="qscore-tip-row"' in main
assert 'class="qscore-tip-rule"' in main
assert 'class="qscore-tip-eq"' in main
assert 'class="qscore-tip-value"' in main
assert "SpamAssassin Rules" in main

# Preserve the approved quarantine five-column layout.
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main

# Native one-line score title must be gone.
assert 'title="${esc(scoreTitle)}"' not in main

print("Milestone 5 Spam Score hover regression test passed")

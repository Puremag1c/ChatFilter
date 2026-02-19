"""Worktree conftest: ensure imports come from worktree, not parent repo."""
import sys
from pathlib import Path

# Insert worktree src at the beginning to override editable install
worktree_src = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(worktree_src))

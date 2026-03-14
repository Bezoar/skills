#!/usr/bin/env bash
#
# Build .skill files from skill directories under skills/
#
# Usage: ./build.sh [skill-name]
#   With no arguments, builds all skills.
#   With a skill name, builds only that skill.
#
# Output: dist/<skill-name>.skill (ZIP archives)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
SKILLS_DIR="$REPO_ROOT/skills"
DIST_DIR="$REPO_ROOT/dist"

build_skill() {
    local skill_name="$1"
    local skill_path="$SKILLS_DIR/$skill_name"

    if [[ ! -f "$skill_path/SKILL.md" ]]; then
        echo "SKIP: $skill_name (no SKILL.md found)"
        return
    fi

    local outfile="$DIST_DIR/${skill_name}.skill"
    rm -f "$outfile"

    # ZIP from inside skills/ so paths are <skill-name>/...
    (cd "$SKILLS_DIR" && find "$skill_name" -type f | sort | zip -q "$outfile" -@)

    local count
    count="$(zipinfo -t "$outfile" 2>/dev/null | grep -o '[0-9]* file' | grep -o '[0-9]*')"
    echo "BUILT: $outfile ($count file(s))"
}

mkdir -p "$DIST_DIR"

if [[ $# -gt 0 ]]; then
    for name in "$@"; do
        if [[ ! -d "$SKILLS_DIR/$name" ]]; then
            echo "ERROR: skill directory not found: skills/$name" >&2
            exit 1
        fi
        build_skill "$name"
    done
else
    found=0
    for skill_path in "$SKILLS_DIR"/*/; do
        [[ -d "$skill_path" ]] || continue
        build_skill "$(basename "$skill_path")"
        found=1
    done
    if [[ $found -eq 0 ]]; then
        echo "No skill directories found in skills/"
        exit 1
    fi
fi

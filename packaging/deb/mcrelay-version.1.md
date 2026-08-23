% MCRELAY-VERSION(1) mcrelay | User Commands
% Bilin Tsui
% July 2026

# NAME

mcrelay-version - print the mcrelay version

# SYNOPSIS

**mcrelay version**

# DESCRIPTION

Print the installed **mcrelay** version in a single line, in the form
`v<display>[+<commit>[-dirty]](<internal>)`. Builds from a clean tagged
commit omit the suffix; clean untagged commits include their abbreviated
commit hash; builds with uncommitted tracked changes append `-dirty` after the hash.
For example: `v1.2-beta10+b0d4fa4-dirty(72)`.

# SEE ALSO

**mcrelay**(1)

Documentation and source: <https://github.com/bilintsui/minecraft-relay-server>

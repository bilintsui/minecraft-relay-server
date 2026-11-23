% MCRELAY-VERSION(1) mcrelay | User Commands
% Bilin Tsui
% July 2026

# NAME

mcrelay-version - print the mcrelay version

# SYNOPSIS

**mcrelay version**

# DESCRIPTION

Print the installed **mcrelay** version in a single line, in the form
`v<display>[+<commit>[-dirty]][-debug][(<internal>)]`. Builds from a clean tagged
commit omit the suffix; clean untagged commits include their abbreviated
commit hash; builds with uncommitted tracked changes append `-dirty` after the hash.
For example: `v1.2-beta10+b0d4fa4-dirty(72)`.

Commit/tag source archives retain their exported commit and tag state even without
Git installed. Changes made after extraction cannot be identified as dirty without
a Git worktree. Source copies without valid archive metadata omit the commit
suffix. A surrounding unrelated Git checkout does not supply version information.
The startup log uses the same version string as this command.

# SEE ALSO

**mcrelay**(1)

Documentation and source: <https://github.com/bilintsui/minecraft-relay-server>

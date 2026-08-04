# Raw packet fixtures

Each `.bin` file contains the first packet sent by an unmodified Minecraft client, captured with `nc -l 25565`. The client used `localhost` as the server address and port `25565`. Usernames were replaced with the equal-length placeholder `testuser1` after capture, preserving every packet length and field boundary.

Some client packets have a corresponding `.bin2` file. These contain the response from an unmodified server after the client's protocol-version field, when present, was incremented by one. They serve as structural references for packets constructed by mcrelay; response text and server-list metadata do not need to match verbatim.

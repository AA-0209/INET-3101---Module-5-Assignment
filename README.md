# INET-3101---Module-5-Assignment

# Problem Statement & Architecture:
  - A client asks for a file by name and the server sends it back over a TCP socket on a set port, handling one client at a time.

# Socket Security & Buffer Analysis:
  - The server reads only as much as its buffer can hold and blocks bad filenames (like ../../etc/passwd) so it can’t be overflowed or tricked into leaking other files.

# Pros & Cons of Solution:
  - It’s simple and safe because it handles one client at a time, but that also means a slow client makes everyone else wait.

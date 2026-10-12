# INET-3101---Module-5-Assignment

# Problem Statement & Architecture

  - A client asks for a text file by name, and the server sends back the file’s contents  over a TCP socket
  - The filename ends with a newline so the server knows where the request stops  and the server closes the connection when it’s done replying
  - The server runs on a set port  and uses SO_REUSEADDR so the port frees up instantly and it can restart right away

# Socket Security & Buffer Analysis

  - Since TCP arrives in pieces the server keeps reading until it finds the newline so a split-up filename still gets reassembled correctly
  - Every read is limited to the space left in the buffer and always null terminated so the server can’t be overflowed by too much input
  - Filenames are checked against a strict whitelist that blocks absolute paths and null bytes so an attack like ../../etc/passwd can never escape the files/ folder

# Pros & Cons of Solution

  - Pro: handling one client at a time is simple and avoids threading bugs or race conditions
  - Pro: strict input limits keep it safe from buffer overflows and file-leaking attacks
  - Con: one client at a time means a slow client makes others wait

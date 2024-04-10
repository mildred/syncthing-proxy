syncthing-proxy
===============

This is a proxy server that does authentication and proxies to unix domain
sockets.

Inspired by:

- https://gist.github.com/yowu/f7dc34bd4736a65ff28d
- https://gist.github.com/teknoraver/5ffacb8757330715bcbcc90e6d46ac74

It will talk with an accountserver daemon to fetch the credentials and use the
username to derive a unix domain socket to forward requests to if the
authentication succeeds.

TODO
====

- [ ] write a wrapper around syncthing that will:

    - acquire a lock file in the sshfs mount point
    - if lock file is acquired, ensure syncthing is running
    - if lock file is released, ensure syncthing is stopped

- [ ] when syncthing is running, bind a public socket and run a reverse proxy
  that forwards to the Syncthing GUI. Add a X-Authorization: bearer UUID of the
  lock file.

- [ ] when syncthing is not running, the wrapper should open the socket
  syncthing would notmally open and run a reverse proxy to the instance that is
  running using the public address of the running service with the correct
  X-Authorization header.

- [ ] Uses HTTPS using a certificate stored on sshfs, or use a encrypted
  transport using a key derived from the UUID shared secret like for example
  https://github.com/nknorg/encrypted-stream

- [ ] For good measures, add an interface to browse the files.

- [ ] Add nice HTML form for the authentication

File locking:

- generate random UUID
- check if the lock file is old (mtime>60s). if stale, remove it 
- take a lock with open(O_CREAT | O_EXCL)
- if lock file cannot be created, wait 30s and repeat
- if lock is taken, write a random UUID to it then close the lock file
- every 30s, check the file exists and contains the UUID
- if not, the lock has been removed from under us, stop services
- if the lock file still exists with the correct UUID, touch it



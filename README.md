**Name: Mitran Andrei-Gabriel**
**Group: 323CA**

## Homework #3 (Asynchronous Web Server)

### Organization:
* This project aims to create an asynchronous web server.
* A connection structure acts as a handler.
* Once a connection is established, requests from clients
are received and responses are sent back.
* The server and clients communicate through HTTP. For parsing, the parser is
used, which in turn uses the callback function to get the path to the local
resource.
* The resources are located in the AWS_DOCUMENT_ROOT subdirectories
(static and dynamic).
* The static files are sent to the clients using sendfile (zero-copying).
* The dynamic files require post-processing: they are read using the async
library functions (such as io_setup) and then sent to the clients.
* For invalid paths, the 404 error message is sent.
* Communication utilizes non-blocking sockets.
* This homework helped me to better understand sockets and helped me learn
how epoll works.
* There could have been better ways of implementing defensive programming,
like instead of using DIE, closing the connection. In case of other errors,
the program may stop, instead of continuing to wait for other connections,
which can be detrimental.

### Implementation:
* Every functionality required for this homework was implemented.
* Learning how to use epoll was both hard and interesting.

### Compilation:
* In order to compile, we use:
```
make
```

### Resources:
* Everything provided by the OS team
* [Linux Manual](https://www.man7.org/linux/man-pages/index.html)
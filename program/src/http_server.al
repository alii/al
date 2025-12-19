// Simple HTTP server example
// Run with: al run --experimental-shitty-io program/src/http_server.al

server = tcp_listen(8080)
println('Listening on http://localhost:8080')

fn loop() {
    conn = tcp_accept(server)

    request = tcp_read(conn)
    println('Got request:')
    println(request)

    body = 'Hello from AL!'
    response = 'HTTP/1.1 200 OK\r\nContent-Length: ' + inspect(14) + '\r\nConnection: close\r\n\r\n' + body

    tcp_write(conn, response)
    tcp_close(conn)

    // Loop forever
    loop()
}

loop()

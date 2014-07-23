/**
 * SOCKS 4:                http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
 * SOCKS 4A:               http://www.openssh.com/txt/socks4a.protocol
 */
var net = require('net'),
    handler5 = require('./library/Handler/SOCKS5');

net.createServer(function(socket) {

    function baseHandler(chunk) {

        socket.removeListener('data', baseHandler);

        switch(chunk[0]) {
            case 5:
                var handler = new handler5(socket);
                handler.handle(chunk);
                return;
            default:
                socket.end();
        }
    }

    socket.on('data', baseHandler);

}).listen(1080);

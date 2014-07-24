var net = require('net'),
    handler5 = require('./library/Handler/SOCKS5'),
    handler4 = require('./library/Handler/SOCKS4');

net.createServer(function(socket) {

    socket.once('data', function(chunk) {

        if(chunk[0] === 5) {
            return new handler5(socket).handle(chunk);
        }

        if(chunk[0] === 4) {
            return new handler4(socket).handle(chunk);
        }

        /**
         * No handler available
         */
        socket.end();

    });

}).listen(1080);

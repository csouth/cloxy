var net = require('net');

function SOCKS5Socket(nodeNetSocket) {

    /**
     * All of these are mostly just to make the code more readable for those not familiar with the RFC
     */
    var addressTypes = {
        ipv4: 1,
        domain: 3,
        ipv6: 4
    };

    var commands = {
        connect: 1,
        bind: 2,
        udpAssociate: 3
    };

    function getHostAndPortFromRequestChunk(chunk) {
        var retVal = {
            host: '',
            port: ''
        };
        portOffset = 4;

        switch(chunk[3]) {
            case addressTypes.ipv4:
                retVal['host'] = [].slice.call(chunk, 4, 8).join('.');
                /*retVal['host'] = [
                    chunk[4],
                    chunk[5],
                    chunk[6],
                    chunk[7]
                ].join('.');*/
                portOffset += 4;
                break;
            case addressTypes.domain:
                retVal['host'] = chunk.toString('utf8', 5, 5 + chunk[4]);
                portOffset += 5+chunk[4];
                break;
            case addressTypes.ipv6:
                retVal['host'] = [].slice.call(chunk, 4, 20).join('.');
                portOffset += 16;
                break;
        }

        console.log(retVal);

        retVal['port'] = chunk.readUInt16BE(portOffset);

        return retVal;
    }

    /**
     * Initial handshake functionality
     *
     * - Grab version
     * - Verify version is 5
     * - Get auth methods
     * - Determine appropriate auth method
     * - Set next appropriate response handler
     * - Send response with chosen auth method
     *
     * @param  Net.Buffer chunk Request sent in by client
     * @return void
     */
    function handshake(chunk) {
        nodeNetSocket.removeListener('data', handshake);

        /**
         * Setting it up for failure...
         */
        var response = Buffer(2);
        response[0] = 5;
        response[1] = 255;

        var version = chunk[0];

        /**
         * This socket handler is only setup for version 5
         */
        if(version !== 5) {
            nodeNetSocket.end(response);
            return;
        }

        var numberOfAuthMethods = chunk[1];
        var selectedAuthMethod = 0;

        /**
         * Figure out which auth method to use - Higher is better
         * TODO - This should check some sort of user setting to determine which to use and which is not a valid option.
         */
        for(i = 2; i <= numberOfAuthMethods + 2; i++) {
            if(chunk[i] < selectedAuthMethod) {
                selectedAuthMethod = chunk[i];
            }
        }

        switch(selectedAuthMethod) {
            case 0: // No authentication
                nodeNetSocket.on('data', processProxyRequest);
                break;
            case 1: // GSS-API authentication
                nodeNetSocket.on('data', authGSSAPI);
                break;
            case 2: // Username and password authentication
                nodeNetSocket.on('data', usernamePasswordAuth);
                break;
            default:
                nodeNetSocket.end(response);
                return;
        }

        /**
         * Tell the client what the chosen auth method will be
         */
        response[1] = selectedAuthMethod;
        nodeNetSocket.write(response);
    }

    function processConnection(chunk) {
        var addressAndPort = getHostAndPortFromRequestChunk(chunk);
        console.log(addressAndPort);
        var connection = net.createConnection(addressAndPort);

        var response = new Buffer(chunk.length);
        chunk.copy(response);
        response[1] = 0;

        nodeNetSocket.write(response);
        nodeNetSocket.on('end', function() {
            connection.removeAllListeners();
            connection.end();
        });
        connection.on('end', function() {
            nodeNetSocket.removeAllListeners();
            nodeNetSocket.end();
        });
        nodeNetSocket.on('data', function(chunk) {
            connection.write(chunk);
        });
        connection.on('data', function(chunk) {
            nodeNetSocket.write(chunk);
        });
    }

    /**
     * Send data back the client after authentication
     * 
     * @param  Net.Buffer chunk Request sent in by client
     * @return void
     */
    function processProxyRequest(chunk) {
        nodeNetSocket.removeListener('data', processProxyRequest);

        switch(chunk[1]) {
            case commands.connect:
                processConnection(chunk);
                break;
            case commands.bind:
                break;
            case commands.udpAssociate:
                break;
        }
    }

    /**
     * Setup inital data handler
     */
    nodeNetSocket.on('data', handshake);
}


net.createServer(function(socket) {new SOCKS5Socket(socket);}).listen(1080);
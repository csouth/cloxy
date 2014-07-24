/**
 * Cloxy  Copyright (C) 2014  Christian South
 * This program comes with ABSOLUTELY NO WARRANTY;
 * This is free software, and you are welcome to redistribute it
 * under certain conditions;
 *
 * DOCUMENTATION:
 * SOCKS 4:                http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
 * SOCKS 4A:               http://www.openssh.com/txt/socks4a.protocol
 */
var net = require('net');

/**
 * SOCKS 4 Handler
 * @param {Net.Socket} socket Socket from Net.createServer connection.
 */
function SOCKS4(socket) {
    /**
     * Socket from server connection
     * @type {Net.Socket}
     */
    this.nodeNetSocket = socket;

    /**
     * Request commands
     * @type {Object}
     */
    this.commands = {
        connect: 1,
        bind: 2,
        dnsConnect: 3
    };

    /**
     * Results
     * @type {Object}
     */
    this.resultCodes = {
        success: 90,
        failed: 91,
        failedNoIdent: 92,
        feildIdentDidNotMatch: 93
    };
}

/**
 * Initial handshake functionality
 *
 * - Grab version
 * - Verify version is 4
 * - Pass request to appropiate processer
 *
 * @param  {Net.Buffer} chunk Request sent in by client
 * @return void
 */
SOCKS4.prototype.handle = function(chunk) {
    /**
     * Wrong version
     */
    if(chunk[0] !== 4) {
        var response = new Buffer(4);
        response[0] = 0;
        response[1] = this.resultCodes.failed;
        response[2] = 0;
        response[3] = 0;
        this.nodeNetSocket.end(response);
    }

    if(chunk[1] === this.commands.connect || chunk[1] === this.commands.dnsConnect) {
        this.processConnectRequest(chunk);
    }
};

/**
 * Process a 'connect' or 'dnsConnect' request
 * 
 * @param  {Net.Bugger} chunk Request sent in by client
 * @return void
 */
SOCKS4.prototype.processConnectRequest = function(chunk) {
    var port =  chunk.readUInt16BE(2);
    var ip   = [].slice.call(chunk, 4, 8).join('.');

    var connection = net.createConnection({host: ip, port: port});

    var response = new Buffer(8);
    response[0] = 0;
    response[1] = this.resultCodes.success;
    response[2] = 0;
    response[3] = 0;
    response[4] = 0;
    response[5] = 0;
    response[6] = 0;
    response[7] = 0;

    this.nodeNetSocket.write(response);
    this.nodeNetSocket.on('end', function() {
        connection.removeAllListeners();
        connection.end();
    });
    connection.on('end', function() {
        this.nodeNetSocket.removeAllListeners();
        this.nodeNetSocket.end();
    }.bind(this));
    this.nodeNetSocket.on('data', function(chunk) {
        connection.write(chunk);
    });
    connection.on('data', function(chunk) {
        this.nodeNetSocket.write(chunk);
    }.bind(this));
};

module.exports = SOCKS4;
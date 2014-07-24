/**
 * Cloxy  Copyright (C) 2014  Christian South
 * This program comes with ABSOLUTELY NO WARRANTY;
 * This is free software, and you are welcome to redistribute it
 * under certain conditions;
 *
 * DOCUMENTATION:
 * SOCKS 5:                http://tools.ietf.org/html/rfc1928
 * SOCKS 5 Authentication: http://tools.ietf.org/html/rfc1929
 * SOCKS 5 GSS-API AUTH:   http://tools.ietf.org/html/rfc1961
 */
var net = require('net');

/**
 * SOCKS 5 Handler
 * @param {Net.Socket} socket Socket from Net.createServer connection.
 */
function SOCKS5(socket) {
    /**
     * Socket from server connection
     * @type {Net.Socket}
     */
    this.nodeNetSocket = socket;

    /**
     * Request address types
     * @type {Object}
     */
    this.addressTypes = {
        ipv4: 1,
        domain: 3,
        ipv6: 4
    };

    /**
     * Request auth methods
     * @type {Object}
     */
    this.authMethods = {
        noAuth: 0,
        gssApi: 1,
        usernamePassword: 2
    };

    /**
     * Request commands
     * @type {Object}
     */
    this.commands = {
        connect: 1,
        bind: 2,
        udpAssociate: 3
    };
}

/**
 * Get the host and port from the process buffer
 * 
 * @param  {Net.Buffer} chunk Proxy buffer
 * @return {Object}           Object containing host and port
 */
SOCKS5.prototype.getHostAndPortFromRequestChunk = function(chunk) {
    var retVal = {
        host: '',
        port: ''
    };
    portOffset = 4;

    switch(chunk[3]) {
        case this.addressTypes.ipv4:
            retVal['host'] = [].slice.call(chunk, 4, 8).join('.');
            portOffset += 4;
            break;
        case this.addressTypes.domain:
            retVal['host'] = chunk.toString('utf8', 5, 5 + chunk[4]);
            portOffset += 5+chunk[4];
            break;
        case this.addressTypes.ipv6:
            /**
             * Yeah, I know this is no where close to right... I'll figure it out later.
             */
            retVal['host'] = [].slice.call(chunk, 4, 20).join('.');
            portOffset += 16;
            break;
    }

    retVal['port'] = chunk.readUInt16BE(portOffset);

    return retVal;
};

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
 * @param  {Net.Buffer} chunk Request sent in by client
 * @return void
 */
SOCKS5.prototype.handle = function(chunk) {
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
        this.nodeNetSocket.end(response);
        return;
    }

    var numberOfAuthMethods = chunk[1];
    var selectedAuthMethod = 0;

    /**
     * Figure out which auth method to use - Higher is better
     * TODO - This should check some sort of user setting to determine which to use and which is not a valid option.
     */
    for(authMethodOffset = 2; authMethodOffset <= numberOfAuthMethods + 2; authMethodOffset++) {
        if(chunk[authMethodOffset] > selectedAuthMethod) {
            selectedAuthMethod = chunk[authMethodOffset];
        }
    }

    if(selectedAuthMethod === 1) {
        // Temp fix until GSS-API is implemented, sometime a long time from now.
        selectedAuthMethod = 0;
    }

    switch(selectedAuthMethod) {
        case this.authMethods.noAuth: // No authentication
            this.nodeNetSocket.once('data', this.processProxyRequest.bind(this));
            break;
        case this.authMethods.usernamePassword: // Username and password authentication
            this.nodeNetSocket.once('data', this.usernamePasswordAuth.bind(this));
            break;
        default:
            this.nodeNetSocket.end(response);
            return;
    }

    /**
     * Tell the client what the chosen auth method will be
     */
    response[1] = selectedAuthMethod;
    this.nodeNetSocket.write(response);
};

/**
 * Process the actual proxy connection
 * 
 * @param  {Net.Buffer} chunk Connection buffer
 * @return {void}
 */
SOCKS5.prototype.processConnection = function(chunk) {
    var addressAndPort = this.getHostAndPortFromRequestChunk(chunk);
    var connection = net.createConnection(addressAndPort);

    var response = new Buffer(chunk.length);
    chunk.copy(response);
    response[1] = 0;

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

/**
 * Handler for the actual proxy request
 * 
 * @param  {Net.Buffer} chunk Request buffer
 * @return {void}
 */
SOCKS5.prototype.processProxyRequest = function(chunk) {
    switch(chunk[1]) {
        case this.commands.connect:
            this.processConnection(chunk);
            break;
        case this.commands.bind:
            break;
        case this.commands.udpAssociate:
            break;
    }
};

/**
 * Authenticate a user based on username and password
 * 
 * @param  {Net.Buffer} chunk Authentication buffer
 * @return {void}
 */
SOCKS5.prototype.usernamePasswordAuth = function(chunk) {
    if(chunk[0] !== 1) {
        // This should never happen, but you know....
        this.nodeNetSocket.end();
        return;
    }

    var userByteCount = chunk[1];
    var passStart     = 3 + userByteCount;
    var passByteCount = chunk[2+userByteCount];
    var user          = chunk.toString('utf8', 2, 2 + userByteCount);
    var pass          = chunk.toString('utf8', passStart, passStart + passByteCount);

    var response = new Buffer(2);
    response[0] = 0x01;

    /**
     * TODO: This need to get usernames and passwords from some internal database...
     */
    if(user !== 'test' || pass !== 'test') {
        response[0] = 0xff;
        this.nodeNetSocket.end(response);
        return;
    }

    response[1] = 0x00;
    this.nodeNetSocket.once('data', this.processProxyRequest.bind(this));
    this.nodeNetSocket.write(response);
};

module.exports = SOCKS5;
const fs = require('fs');
const dgram = require('dgram');
const protobuf = require('protobufjs');
const sodium = require('libsodium-wrappers');
const readline = require('readline');
const commandLineArgs = require('command-line-args');
const optionDefinitions = [
	{ name: 'server', alias: 's', type: String, defaultValue: '127.0.0.1' },
	{ name: 'port', alias: 'p', type: Number, defaultValue: 1234 },
	{ name: 'pub', type: String },
	{ name: 'priv', type: String },
	{ name: 'sk', type: String },
	{ name: 'help', alias: 'h', type: Boolean }
];
const options = commandLineArgs(optionDefinitions);

const NONCE_SIZE = 12;
const MAC_SIZE = 16;
const OBDI_MARKER = [79, 66, 68, 73];
const OBDI_VERSION = 0;

var socket = dgram.createSocket('udp4');

var obdi;
var crypto;
var client_id = 1;
var sign_pk, sign_sk, server_sign_pk;
var client_pk_path = options['pub'];
var client_sk_path = options['priv'];
var server_pk_path = options['sk'];
var address = options['server'];
var port = options['port'];
var MessageType;
var Notice, Ping, Ack, CryptoError, LocationUpdate, TripInfoUpdateStatus, ChangeSettings, Error, ETAUpdate, TripInfoUpdate;

var ClientMessageHeader = function() {
	this.marker = OBDI_MARKER;
	this.version = OBDI_VERSION;
	this.payload_size = 0;
	this.message_type = 0;
	this.vessel_id = 0;
};

ClientMessageHeader.prototype.toBuffer = function() {
	var buffer = Buffer.alloc(16);
	buffer.writeUInt8(this.marker[0], 0);
	buffer.writeUInt8(this.marker[1], 1);
	buffer.writeUInt8(this.marker[2], 2);
	buffer.writeUInt8(this.marker[3], 3);	
	buffer.writeUInt8(this.version, 4);
	buffer.writeUInt8(MessageType[this.message_type.name], 5);
	buffer.writeUInt16LE(this.payload_size, 6);
	buffer.writeUIntLE(this.vessel_id, 8, 8);
	return buffer;
};

var ServerMessageHeader = function() {
	this.marker = OBDI_MARKER;
	this.version = OBDI_VERSION;
	this.payload_size = 0;
	this.message_type = 0;
};

ServerMessageHeader.prototype.fromBuffer = function(buffer) {
	this.marker = buffer.slice(0, 4);
	this.version = buffer.readUInt8(4);
	this.payload_size = buffer.readUInt16LE(5);
	this.message_type = buffer.readUInt8(7);
};

var ClientCrypto = function(sign_pk, sign_sk, server_sign_pk) {
	this.sign_pk = sign_pk;
	this.sign_sk = sign_sk;
	this.server_sign_pk = server_sign_pk;
	this.derive_keys();
};

ClientCrypto.prototype.derive_keys = function() {
	this.client_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(this.sign_pk);
	this.client_sk = sodium.crypto_sign_ed25519_sk_to_curve25519(this.sign_sk);
	this.server_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(this.server_sign_pk);
	var session_keys = sodium.crypto_kx_client_session_keys(this.client_pk, this.client_sk, this.server_pk);
	this.client_tx = session_keys.sharedTx;
	this.client_rx = session_keys.sharedRx;
};

ClientCrypto.prototype.encrypt_payload = function(header, payload) {
	var nonce = sodium.randombytes_buf(NONCE_SIZE);
	var res = sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(payload, header, null, nonce,
		this.client_tx);

	return {
		encrypted_bytes: Buffer.from(res.ciphertext.buffer),
		nonce_bytes: Buffer.from(nonce.buffer),
		mac_bytes: Buffer.from(res.mac.buffer)
	};
};

ClientCrypto.prototype.decrypt_payload = function(header, payload) {
	var header_nonce = header.slice(8, 20);
	var header_mac = header.slice(20, 36);

	return sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(null, payload, header_mac, header.slice(0, 8), header_nonce, this.client_rx);
};

function initialized() {
	return sign_pk != undefined && sign_sk != undefined && server_sign_pk != undefined && obdi != undefined;
}

fs.readFile(client_pk_path, function(err, data) {
	if(err) throw err;
	sign_pk = new Uint8Array(data);
	if(initialized()) main();
});

fs.readFile(client_sk_path, function(err, data) {
	if(err) throw err;
	sign_sk = new Uint8Array(data);
	if(initialized()) main();
});

fs.readFile(server_pk_path, function(err, data) {
	if(err) throw err;
	server_sign_pk = new Uint8Array(data);
	if(initialized()) main();
});

function prepare_message(message, type) {
	var message_bytes = type.encode(message).finish();
	var header_bytes = Buffer.alloc(16);
	var client_header = new ClientMessageHeader();
	client_header.marker = OBDI_MARKER;
	client_header.version = OBDI_VERSION;
	client_header.message_type = type;
	client_header.payload_size = message_bytes.length;
	client_header.vessel_id = client_id;
	var header_bytes = client_header.toBuffer();

	var res = crypto.encrypt_payload(header_bytes, message_bytes);
	return Buffer.concat([header_bytes, res.nonce_bytes, res.mac_bytes, res.encrypted_bytes]);
}

protobuf.load('../../obdi.proto', function(err, root) {
	if(err) throw err;
	obdi = root;

	Notice = obdi.lookupType('obdi.Notice');
	Ping = obdi.lookupType('obdi.Ping');
	Ack = obdi.lookupType('obdi.Ack');
	CryptoError = obdi.lookupType('obdi.CryptoError');
	LocationUpdate = obdi.lookupType('obdi.LocationUpdate');
	TripInfoUpdateStatus = obdi.lookupType('obdi.TripInfoUpdateStatus');
	ChangeSettings = obdi.lookupType('obdi.ChangeSettings');
	Error = obdi.lookupType('obdi.Error');
	ETAUpdate = obdi.lookupType('obdi.ETAUpdate');
	TripInfoUpdate = obdi.lookupType('obdi.TripInfoUpdate');

	MessageType = {
		Notice: 0,
		Ping: 2,
		Ack: 3,

		CryptoError: 10,
		
		LocationUpdate: 20,
		TripInfoUpdateStatus: 21,

		ChangeSettings: 50,
		Error: 51,
		ETAUpdate: 52,
		TripInfoUpdate: 53
	};

	if(initialized()) main();
});

var message_id_counter = 1;
function getMessageId() {
	return message_id_counter++;
}

function getCurrentTime() {
	return {seconds: parseInt(Date.now() / 1000, 10), nanos: 0|0 };
}

function main() {
	crypto = new ClientCrypto(sign_pk, sign_sk, server_sign_pk);

	var ping = Ping.create({messageId: 1|0, timeGenerated: getCurrentTime()});
	var send_buffer = prepare_message(ping, Ping);
	socket.send(send_buffer, 0, send_buffer.length, port, address);

	var rl = readline.createInterface({input: process.stdin, output: process.stdout});
	rl.setPrompt('client: ' + client_id + '> ');
	rl.prompt();

	rl.on('line', function(text) {
		var split = text.split(' ');
		if(split[0] == 'q') {
			process.exit(0);
		}
		if(split[0] == 'notice') {
			var notice_message = split[1];
			var severity = parseInt(split[2]);

			if(notice_message == undefined || isNaN(severity)) {
				console.log('Invalid arguments. Type \"help notice\" for more information.');
				return;
			}

			//TODO Quoted strings
			var notice_message = split[1];
			var severity = parseInt(split[2]);

			var notice = Notice.create({messageId: getMessageId(), timeGenerated: getCurrentTime(), severity: severity, details: notice_message});
			var send_buffer = prepare_message(notice, Notice);
			socket.send(send_buffer, 0, send_buffer.length, port, address);
		}
		if(split[0] == 'ping') {
			var ping = Ping.create({messageId: getMessageId(), timeGenerated: getCurrentTime()});
			
			var send_buffer = prepare_message(ping, Ping);
			socket.send(send_buffer, 0, send_buffer.length, port, address);
		}
		if(split[0] == 'lu') {
			var longitude = parseFloat(split[1]);
			var latitude = parseFloat(split[2]);
			var bearing = parseFloat(split[3]);
			var speed = parseFloat(split[4]);
			var current_load = parseInt(split[5]);
			var status = parseInt(split[6]);
			var current_trip_id = parseInt(split[7]);
			var stop = parseInt(split[8]);	

			if(isNaN(longitude) || isNaN(latitude) || isNaN(bearing) || isNaN(speed) || isNaN(current_load) || isNaN(status) || isNaN(current_trip_id) || isNaN(stop)) {
				console.log('Invalid arguments. Type "help lu" for more information.');
				return;
			}

			var luObject = {entries: []};
			luObject.entries[0] = {
				longitude: longitude,
				latitude: latitude,
				bearing: bearing,
				speed: speed,
				currentLoad: current_load,
				status: status,
				currentTripId: current_trip_id,
				stop: stop
			};

			var lu = LocationUpdate.create(luObject);
			var send_buffer = prepare_message(lu, LocationUpdate);
			socket.send(send_buffer, 0, send_buffer.length, port, address);
		} else {
			if(split[0] == 'help') {
				if(split[1] == 'notice') {
					console.log('notice message severity');
					console.log('\tmessage - String to send, use quotes if the message contains spaces.')
					console.log('\tseverity - Integer from 0 to 6 stating the severity associated with the message. See OBDI documentation for severity details.');
				} else if(split[1] == 'lu') {
					console.log('lu longitude latitude bearing speed current_load status current_strip_id stop');
				} else if(split[1] == undefined) {
					console.log('List of commands:');
					console.log('\tnotice - Sends a notice message.');
					console.log('\tping - Sends a ping message.');
					console.log('\tlu - Sends a location update.');
					console.log('\tq - Quits the client.');
					console.log('\thelp - Print commands and command information.');
				}
			}
		}
   	});

	socket.on('message', function(message, remote) {
		var header_bytes = message.slice(0, 36);
		var payload_bytes = message.slice(36);
		var decrypted = crypto.decrypt_payload(header_bytes, payload_bytes);
		var header = new ServerMessageHeader();
		header.fromBuffer(header_bytes);

		var address = remote.address;
		var port = parseInt(remote.port);

		if(header.message_type == MessageType[Notice.name]) {
			var notice = Notice.decode(decrypted);
			console.log("Recieved from server: " , notice);

			var ack = Ack.create({messageId: notice.messageId, timeGenerated: getCurrentTime()});
			var send_buffer = prepare_message(ack, Ack);

			socket.send(send_buffer, 0, send_buffer.length, port, address);
		} else if(header.message_type == MessageType[Ping.name]) {
			var ping = Ping.decode(decrypted);
			console.log("Recieved from server: ", ping);

			var ack = Ack.create({messageId: ping.messageId, timeGenerated: getCurrentTime()});
			var send_buffer = prepare_message(ack, Ack);

			socket.send(send_buffer, 0, send_buffer.length,	port, address);
		} else if(header.message_type == MessageType[Ack.name]) {
			var ack = Ack.decode(decrypted);
			console.log("Recieved from server: ", ack);
		} else if(header.message_type == MessageType[CryptoError.name]) {
			var crypto_error = CryptoError.decode(decrypted);
			console.log("Recieved from server: ", crypto_error);
		} else if(header.message_type == MessageType[ChangeSettings.name]) {
			var change_settings = ChangeSettings.decode(decrypted);
			console.log("Recieved from server: ", change_settings);

			var ack = Ack.create({messageId: ping.messageId, timeGenerated: getCurrentTime()});
			var send_buffer = prepare_message(ack, Ack);

			socket.send(send_buffer, 0, send_buffer.length,	port, address);
		} else if(header.message_type == MessageType[Error.name]) {
			var error = Error.decode(decrypted);
			console.log("Recieved from server: ", error);
		} else if(header.message_type == MessageType[ETAUpdate.name]) {
			var etaUpdate = ETAUpdate.decode(decrypted);
			console.log("Recieved from server: ", etaUpdate);
		} else if(header.message_type == MessageType[TripInfoUpdate.name]) {
			var tripInfoUpdate = TripInfoUpdate.decode(decrypted);
			console.log("Recieved from server: ", tripInfoUpdate);

			var response = TripInfoUpdateStatus.create({updateId: tripInfoUpdate.updateId, status: 0});
			var send_buffer = prepare_message(response, TripInfoUpdateStatus);

			socket.send(send_buffer, 0, send_buffer.length, port, address);
		} else {
			console.log("[WARNING] Unknown message type: ", header.message_type);
		}
	});
}

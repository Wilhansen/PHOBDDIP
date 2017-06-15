const fs = require('fs');
const dgram = require('dgram');
const protobuf = require('protobufjs');
const sodium = require('libsodium-wrappers');
const NONCE_SIZE = 12;
const MAC_SIZE = 16;
const OBDI_MARKER = [79, 66, 68, 73];
const OBDI_VERSION = 0;

var socket = dgram.createSocket('udp4');

var obdi;
var crypto;
var client_id = 1;
var sign_pk, sign_sk, server_sign_pk;
var client_pk_path = process.argv[2];
var client_sk_path = process.argv[3];
var server_pk_path = process.argv[4];
var MessageType;
var Notice, Ping, Ack, CryptoError, LocationUpdate, TripInfoUpdateStatus, ChangeSettings, Error, ETAUpdate, TripInfoUpdate;

var ClientCrypto = function(sign_pk, sign_sk, server_sign_pk) {
	this.sign_pk = sign_pk;
	this.sign_sk = sign_sk;
	this.server_sign_pk = server_sign_pk;	
	this.derive_keys();
};

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
	var header_marker = header.slice(0, 4);
	var header_version = header.readUInt8(4);
	var header_payload_size = header.readUInt16LE(5);
	var header_message_type = header.readUInt8(7);
	var header_nonce = header.slice(8, 20);
	var header_mac = header.slice(20, 36);

	var res = sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(null, payload, header_mac, header.slice(0, 8), header_nonce, this.client_rx);
	console.log(res);
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

function main() {
	crypto = new ClientCrypto(sign_pk, sign_sk, server_sign_pk);

	var Notice = obdi.lookupType('obdi.Notice');
	var Ping = obdi.lookupType('obdi.Ping');
	var VesselStatus = obdi.lookup('obdi.VesselStatus');
	var Severity = obdi.lookup('obdi.Severity');

	var now = parseInt(Date.now() / 1000, 10);
	var ping = Ping.create({messageId: 1|0, timeGenerated: {seconds: now, nanos: 0|0 }});
	var send_buffer = prepare_message(ping, Ping);

	socket.send(send_buffer, 0, send_buffer.length, 1234, '127.0.0.1', function(err, bytes) {
		if(err) throw err;
	});

	socket.on('message', function(message, remote) {
		var header_bytes = message.slice(0, 36);
		var payload_bytes = message.slice(36);
		var decrypted = crypto.decrypt_payload(header_bytes, payload_bytes);
		
	});
}

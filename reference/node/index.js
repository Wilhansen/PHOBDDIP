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

var ClientMessageHeader = function() {
	this.marker = OBDI_MARKER; 
	this.version = OBDI_VERSION;
	this.message_type = 0;
	this.payload_size = 0;
	this.vessel_id = 0;
	this.payload_ad = null;	
}

var MessageType;
var Notice, Ping, Ack, CryptoError, LocationUpdate, TripInfoUpdateStatus, ChangeSettings, Error, ETAUpdate, TripInfoUpdate;

function prepare_message(message, type) {
	var message_bytes = type.encode(message).finish();
	var header_bytes = Buffer.alloc(16);
	header_bytes.writeUInt8(OBDI_MARKER[0], 0);
	header_bytes.writeUInt8(OBDI_MARKER[1], 1);
	header_bytes.writeUInt8(OBDI_MARKER[2], 2);
	header_bytes.writeUInt8(OBDI_MARKER[3], 3);
	header_bytes.writeUInt8(OBDI_VERSION, 4);
	header_bytes.writeUInt8(MessageType[type.name], 5);
	header_bytes.writeUInt16LE(message_bytes.length, 6);
	header_bytes.writeUIntLE(client_id, 8, 8);

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

		CryptoErrpr: 10,
		
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
	var ping = Ping.create({messageId: 12|0, timeGenerated: {seconds: now, nanos: 0|0 }});
	var send_buffer = prepare_message(ping, Ping);

	socket.send(send_buffer, 0, send_buffer.length, 1234, '127.0.0.1', function(err, bytes) {
		if(err) throw err;
		socket.close();
	});
}

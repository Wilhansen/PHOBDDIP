const fs = require('fs');
const dgram = require('dgram');
const protobuf = require('protobufjs');
const sodium = require('libsodium-wrappers');
const NONCE_SIZE = 12;
const MAC_SIZE = 16;

var socket = dgram.createSocket('udp4');

var obdi;
var crypto;
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
	this.marker = [79, 66, 68, 73];
	this.version = 0;
	this.message_type = 0;
	this.payload_size = 0;
	this.vessel_id = 0;
	this.payload_ad = null;	
}

protobuf.load('../../obdi.proto', function(err, root) {
	if(err) throw err;
	obdi = root;
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
	var ping_bytes = Ping.encode(ping).finish();

	var header = new ClientMessageHeader();
	header.version = 0;
	header.message_type = 2;
	header.payload_size = ping_bytes.length;
	header.vessel_id = 1;
	var nonce = sodium.randombytes_buf(NONCE_SIZE);
	var header_bytes = Buffer.alloc(16);
	header_bytes.writeUInt8(header.marker[0], 0);
	header_bytes.writeUInt8(header.marker[1], 1);
	header_bytes.writeUInt8(header.marker[2], 2);
	header_bytes.writeUInt8(header.marker[3], 3);
	header_bytes.writeUInt8(header.version, 4);
	header_bytes.writeUInt8(header.message_type, 5);
	header_bytes.writeUInt16LE(header.payload_size, 6);
	header_bytes.writeUIntLE(header.vessel_id, 8, 8);

	var res = crypto.encrypt_payload(header_bytes, ping_bytes);
	var send_buffer = Buffer.concat([header_bytes, res.nonce_bytes, res.mac_bytes, res.encrypted_bytes]);

	socket.send(send_buffer, 0, send_buffer.length, 1234, '127.0.0.1', function(err, bytes) {
		if(err) throw err;
		socket.close();
	});
}

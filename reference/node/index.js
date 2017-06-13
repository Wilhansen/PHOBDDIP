const fs = require('fs');
const dgram = require('dgram');
const protobuf = require('protobufjs');
const sodium = require('libsodium-wrappers');
const NONCE_SIZE = 12;
const MAC_SIZE = 16;

var socket = dgram.createSocket('udp4');

var obdi;
var sign_pk, sign_sk, server_sign_pk;
var client_pk_path = process.argv[2];
var client_sk_path = process.argv[3];
var server_pk_path = process.argv[4];

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

	var client_pk, client_sk, server_pk,
		client_tx, client_rx;

	client_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(sign_pk);
	client_sk = sodium.crypto_sign_ed25519_sk_to_curve25519(sign_sk);
	server_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(server_sign_pk);

	var session_keys = sodium.crypto_kx_client_session_keys(client_pk, client_sk, server_pk);
	client_tx = session_keys.sharedTx;
	client_rx = session_keys.sharedRx;

	var Notice = obdi.lookupType('obdi.Notice');
	var Ping = obdi.lookupType('obdi.Ping');
	var VesselStatus = obdi.lookup('obdi.VesselStatus');
	var Severity = obdi.lookup('obdi.Severity');

	var now = parseInt(Date.now() / 1000, 10);
	var ping = Ping.create({messageId: 12|0, timeGenerated: {seconds: now, nanos: 0|0 }});
	var ping_bytes = Ping.encode(ping).finish();

	var header = new ClientMessageHeader();
	header.payload_size = ping_bytes.length;
	header.message_type = 2;
	header.payload_ad = {
		nonce: sodium.randombytes_buf(NONCE_SIZE), 
		mac: null
	};
	var encrypted = sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(ping_bytes, header_bytes, null, header.payload_ad.nonce, client_tx);
	header.payload_ad.mac = encrypted.mac;

	var header_arr = [header.marker[0], header.marker[1], header.marker[2], header.marker[3], header.version, header.message_type, header.payload_size, header.vessel_id];
	var nonce_bytes = Buffer.from(header.payload_ad.nonce.buffer);
	var mac_bytes = Buffer.from(header.payload_ad.mac.buffer);
	var header_bytes = Buffer.from(header_arr);
	
	var send_buffer = Buffer.concat([header_bytes, nonce_bytes, mac_bytes, ping_bytes]);
	console.log(header_bytes.length, nonce_bytes.length, mac_bytes.length, ping_bytes.length);

	socket.send(send_buffer, 0, send_buffer.length, 1234, '127.0.0.1', function(err, bytes) {
		if(err) throw err;
		socket.close();
	});
}

#include "Utility.hpp"

#include <stdexcept>
#include <sstream>

#include <sodium.h>

using namespace std;

SecureMemory::SecureMemory(size_t size) : m_size(size) {
	m_data = new uint8_t[size];
	sodium_mlock(m_data, m_size);
}

SecureMemory::~SecureMemory() {
	if ( m_data == 0 ) return;

	sodium_memzero(m_data, m_size);
	sodium_munlock(m_data, m_size);

	delete [] m_data;
}

KeyPair KeyPair::generate() {
	KeyPair kp = {SecureMemory(crypto_sign_ed25519_PUBLICKEYBYTES), SecureMemory(crypto_sign_ed25519_SECRETKEYBYTES)};

	crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data());
	return kp;
}

ServerCrypto::ServerCrypto(const char *keydir) : m_keydir(keydir), server_sk(crypto_kx_SECRETKEYBYTES), sign_sk(crypto_sign_ed25519_SECRETKEYBYTES) {
	if (!m_keydir.empty()) {
		if (m_keydir[m_keydir.size() - 1] != '/' ) {
			m_keydir += '/';
		}
	}
	sign_pk = readfile((m_keydir + SERVER_PUBLIC_KEY_FILE).c_str());
	if ( sign_pk.empty() ) {
		throw runtime_error("Cannot read " SERVER_PUBLIC_KEY_FILE ".");
	}

	if ( sign_pk.size() != crypto_sign_ed25519_PUBLICKEYBYTES ) {
		throw runtime_error("Wrong size for " SERVER_PUBLIC_KEY_FILE ".");
	}

	if ( FILE *fp = fopen((m_keydir + SERVER_PRIVATE_KEY_FILE).c_str(), "rb") ) {
		const auto len = fread(sign_sk.data(), 1, sign_sk.size(), fp);
		fclose(fp);
		if ( len != sign_sk.size() ) {
			throw runtime_error("Wrong size for " SERVER_PRIVATE_KEY_FILE ".");
		}
	} else {
		throw runtime_error("Cannot open " SERVER_PRIVATE_KEY_FILE ".");
	}

	//derive the encryption pk/sk from the signature sk
	server_pk.resize(crypto_kx_PUBLICKEYBYTES);
	if ( crypto_sign_ed25519_pk_to_curve25519(server_pk.data(), sign_pk.data()) != 0 ) {
		throw runtime_error("Invalid server public key provided.");
	}
	if ( crypto_sign_ed25519_sk_to_curve25519(server_sk.data(), sign_sk.data()) != 0 ) {
		throw runtime_error("Invalid server private key provided.");	
	}
}

namespace {
	string client_keyfile(const uint64_t client_id) {
		char buffer[64] = { 0 };
		sprintf(buffer, "%16llX.pub", client_id);
		return string(buffer);
	}
}

//-----------------ServerCrypto-------------------
ServerCrypto::Result ServerCrypto::load_keys(const uint64_t client_id, SessionKeyPair &dst) {
	const auto client_keypath = m_keydir + client_keyfile(client_id);
	const auto client_sign_pk = readfile(client_keypath.c_str());
	if ( client_sign_pk.empty() ) {
		return KEY_NOT_FOUND;
	}
	if ( client_sign_pk.size() != crypto_sign_ed25519_SECRETKEYBYTES ) {
		return WRONG_CLIENT_KEY_SIZE;
	}

	vector<uint8_t> client_pk(crypto_kx_PUBLICKEYBYTES);
	crypto_sign_ed25519_pk_to_curve25519(client_pk.data(), client_sign_pk.data());	

	SecureMemory reception_key(crypto_kx_SESSIONKEYBYTES),
				 transmisson_key(crypto_kx_SESSIONKEYBYTES);

	if ( !crypto_kx_server_session_keys(reception_key.data(), transmisson_key.data(), server_pk.data(), server_sk.data(), client_pk.data()) ) {
		return WRONG_KEY;
	}

	dst.reception_key = move(reception_key);
	dst.transmisson_key = move(transmisson_key);

	return OK;
}

ServerCrypto::Result ServerCrypto::decrypt_payload(const uint64_t client_id, const PayloadHeader &payload_header, void *payload) {
	SessionKeyPair kp;
	Result r;
	if ( (r = load_keys(client_id, kp)) != OK ) {
		return r;
	}

	if ( !crypto_secretbox_open_detached((uint8_t*)payload, (uint8_t*)payload,
		payload_header.mac, payload_header.payload_size,
		payload_header.nonce, kp.reception_key.data()) ) {
		return INVALID_PAYLOAD;
	} else {
		return OK;
	}
}

ServerCrypto::Result ServerCrypto::encrypt_payload(const uint64_t client_id, PayloadHeader &payload_header, const void *payload, void *destination) {
	SessionKeyPair kp;
	Result r;
	if ( (r = load_keys(client_id, kp)) != OK ) {
		return r;
	}
	randombytes_buf(payload_header.nonce, NONCE_SIZE);
	crypto_secretbox_detached((uint8_t*)destination, payload_header.mac, (const uint8_t*)payload,
		payload_header.payload_size, payload_header.nonce,
		kp.transmisson_key.data());
	return OK;
}

void ServerCrypto::sign_payload(const void *payload, PayloadHeader &header) {
	crypto_sign_detached(header.signature, NULL,(const uint8_t*)payload, header.payload_size, sign_sk.data());
}


//-----------------ClientCrypto-------------------

ClientCrypto::ClientCrypto(const uint64_t client_id, const char *pk_path, const char *sk_path, const char *server_key_path) :
client_id(client_id), client_rx(crypto_kx_SESSIONKEYBYTES), client_tx(crypto_kx_SESSIONKEYBYTES), sign_sk(crypto_sign_ed25519_SECRETKEYBYTES) {
	server_sign_pk = readfile(server_key_path);
	sign_pk = readfile(pk_path);

	if ( FILE *fp = fopen(sk_path, "rb") ) {
		const auto len = fread(sign_sk.data(), 1, sign_sk.size(), fp);
		fclose(fp);
		if ( len != sign_sk.size() ) {
			throw runtime_error(string("Wrong size for ") + sk_path);
		}
	} else {
		throw runtime_error(string("Cannot open ") + sk_path);
	}

	vector<uint8_t> client_pk(crypto_kx_PUBLICKEYBYTES),
					server_pk(crypto_kx_PUBLICKEYBYTES);
	SecureMemory client_sk(crypto_kx_SECRETKEYBYTES);

	if ( crypto_sign_ed25519_pk_to_curve25519(client_pk.data(), sign_pk.data()) != 0 ) {
		throw runtime_error("Invalid client public key provided.");
	}
	if ( crypto_sign_ed25519_sk_to_curve25519(client_sk.data(), sign_sk.data()) != 0 ) {
		throw runtime_error("Invalid client private key provided.");	
	}

	if ( crypto_sign_ed25519_pk_to_curve25519(server_pk.data(), server_sign_pk.data()) != 0 ) {
		throw runtime_error("Invalid server public key provided.");
	}

	crypto_kx_client_session_keys(client_rx.data(), client_tx.data(), client_pk.data(), client_sk.data(), server_pk.data());
}

ClientCrypto::Result ClientCrypto::decrypt_payload(const PayloadHeader &payload_header, void *payload) {
	if ( !crypto_secretbox_open_detached((uint8_t*)payload, (uint8_t*)payload,
		payload_header.mac, payload_header.payload_size,
		payload_header.nonce, client_rx.data()) ) {
		return INVALID_PAYLOAD;
	} else {
		return OK;
	}
}

ClientCrypto::Result ClientCrypto::encrypt_payload(PayloadHeader &payload_header, const void *payload, void *destination) {
	randombytes_buf(payload_header.nonce, NONCE_SIZE);
	crypto_secretbox_detached((uint8_t*)destination, payload_header.mac, (const uint8_t*)payload,
		payload_header.payload_size, payload_header.nonce,
		client_tx.data());
	return OK;
}

void ClientCrypto::sign_payload(const void *payload, PayloadHeader &header) {
	crypto_sign_detached(header.signature, NULL,(const uint8_t*)payload, header.payload_size, sign_sk.data());
}

bool ClientCrypto::verify_signed_server_payload(const void *payload, const PayloadHeader &header) {
	return crypto_sign_verify_detached(header.signature, (const uint8_t*)payload, header.payload_size, server_sign_pk.data()) == 0;
}

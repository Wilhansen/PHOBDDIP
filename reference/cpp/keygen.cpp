#include <fstream>
#include <iostream>
#include <string>

#include "Utility.hpp"

using namespace std;

int main(int argc, char **argv) {
	if ( argc == 1 ) {
		cout 	<< "Key pair generator. Usage: \n"
				<< argv[0] << " name\n"
				<< "\t Generates a key pair and writes the public and secret key to name.pub and name.key respectively.\n"
				<< argv[0] << " public.pub secret.key\n"
				<< "\t Generates a key pair. The public key goes to public.pub and the secret key to secret.key.\n";
		return 0;
	}
	string pk_path, sk_path;

	pk_path = argv[1];
	if ( argc == 2 ) {
		pk_path += ".pub";

		sk_path = argv[1];
		sk_path += ".key";
	} else {
		sk_path = argv[2];
	}

	auto kp = KeyPair::generate();

	{
		ofstream pk(pk_path.c_str());
		if ( !pk ) {
			cerr << "Unable to write public key to " << pk_path << endl;
			return 1;
		}
		pk.write((char*)kp.public_key.data(), kp.public_key.size());
	}
	
	{
		ofstream sk(sk_path.c_str());
		if ( !sk ) {
			cerr << "Unable to write secret key to " << sk_path << endl;
			return 1;
		}
		sk.write((char*)kp.secret_key.data(), kp.secret_key.size());
	}
	return 0;
}
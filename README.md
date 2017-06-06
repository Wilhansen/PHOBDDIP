# OBD Data Interchange Protocol

## Building the reference client/server
1. Install libsodium (1.0.12) and protobuf (3.3.0)
2. Compile the OBDI proto file
	protoc --c_out=/reference/cpp/ obdi.proto
3. Compile the source files using make
4. Run server and client separately

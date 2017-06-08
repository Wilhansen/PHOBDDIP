# OBD Data Interchange Protocol

## Building
1. Install libsodium (1.0.12) and protobuf (3.3.0)
2. Compile the OBDI proto file using  
`protoc --cpp_out=/reference/cpp/ obdi.proto`
3. Compile the source files using make

## Running
1. Generate the keys, save to their default location
`./keygen keys/server`  
`./keygen client.pub client.priv`
2. Copy the client.pub key to the keys directory, rename it 0000000000000001.pub (default client id = 1)
3. Run server and client
4. Send messages from the client command line (`help` to show commands)

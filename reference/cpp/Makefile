all: server keygen client

client: client.cpp Utility.cpp Utility.hpp obdi.pb.cc
	$(CXX) $(CXXFLAGS) -o client -std=c++14 client.cpp Utility.cpp obdi.pb.cc `pkg-config --cflags --libs libsodium protobuf` 

server: server.cpp Utility.cpp Utility.hpp obdi.pb.cc
	$(CXX) $(CXXFLAGS) -o server -std=c++11 server.cpp Utility.cpp obdi.pb.cc `pkg-config --cflags --libs protobuf libsodium`

keygen: keygen.cpp Utility.cpp Utility.hpp
	$(CXX) $(CXXFLAGS) -o keygen -std=c++11 keygen.cpp Utility.cpp `pkg-config --cflags --libs libsodium` 

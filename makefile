crack : crack.cpp
		g++ -std=c++11 crack.cpp -o crack -pthread -lssl -lcrypto -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include

fedora : crack.cpp
		g++ -std=c++11 crack.cpp -o crack -lcrypto -pthread

clean : 
			rm crack

crack : crack.cpp
		g++ -std=c++11 crack.cpp -o crack -lssl -lcrypto -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include

clean : 
			rm crack

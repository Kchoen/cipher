#include "rsa.h"
#include "osrng.h"
#include <string>
#include<iostream>
#include<stdlib.h>
#include<time.h>
// random number generator
using namespace CryptoPP;
using namespace std;
char guess[] = "0x53a0a95b089cf23adb5cc73f0700000";
AutoSeededRandomPool prng;
char set[] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
void printAllKLengthRec( string prefix,
	int n, int k)
{

	// Base case: k is 0,
	// print prefix
	if (k == 0)
	{
		guess[32] = prefix[4];
		guess[31] = prefix[3];
		guess[30] = prefix[2];
		guess[29] = prefix[1];
		guess[28] = prefix[0];
		try {
			Integer n("0xc4b361851de35f080d3ca7352cbf372d"), e("0x1d35"), d(guess);
			RSA::PrivateKey privKey;
			privKey.Initialize(n, e, d);
			Integer c("0xa02d51d0e87efe1defc19f3ee899c31d"), r;
			string recovered;
			
			// Decrypt
			r = privKey.CalculateInverse(prng, c);
			cout << "guess : " << hex << guess << endl;
			cout << "r:" << hex << r << endl;

			// Round trip the message
			size_t req = r.MinEncodedSize();
			recovered.resize(req);
			r.Encode((byte*)recovered.data(), recovered.size());

			cout << "recovered:" << recovered << endl;
		}
		catch (...) {
			;
		}
		return;
	}

	// One by one add all characters
	// from set and recursively
	// call for k equals to k-1
	for (int i = 0; i < n; i++)
	{
		string newPrefix;

		// Next character of input added
		newPrefix = prefix + set[i];

		// k is decreased, because
		// we have added a new character
		printAllKLengthRec(newPrefix, n, k - 1);
	}

}

void printAllKLength(int k, int n)
{
	printAllKLengthRec("", n, k);
}
int main() {
	int key_length = 128;

	////Integer n("0xc963f963d93559ff"), e("0x11");
	//Integer n("0x9711ea5183d50d6a91114f1d7574cd52621b35499b4d3563ec95406a994099c9"), e("0x10001");
	////string message = "Hello World!";
	//string message = "RSA is public key.";
	//RSA::PublicKey pubKey;
	//pubKey.Initialize(n, e);

	///////////////////////////////////////////////////////////
	//Integer  m, c;

	//cout << "message:" << message << endl;

	//// Treat the message as a big endian byte array
	//m = Integer((const byte*)message.data(), message.size());
	//cout << "m:" << hex << m << endl;

	//// Encrypt
	//c = pubKey.ApplyFunction(m);
	//cout << "c:" << hex << c << endl;


	char fivebyte[5];
	srand(time(0));
	

	printAllKLength(5, 16);
		
	
	


	return 0;
}
// EllipticcurveSignature.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDSA;

#include "sha.h"
using CryptoPP::SHA1;

#include "queue.h"
using CryptoPP::ByteQueue;

#include "oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "asn.h"
using namespace CryptoPP::ASN1;

#include "integer.h"
using CryptoPP::Integer;

#include "files.h"
#include "hex.h"
#include "base64.h"
using namespace CryptoPP;
int _tmain(int argc, _TCHAR* argv[])
{

	/*
	CryptoPP::SHA256 hash;
	byte digest[CryptoPP::SHA256::DIGESTSIZE];
	std::string username, password, salt, output;
	std::cout << "Enter username: ";
	std::getline(std::cin, username);
	std::cout << std::endl << "Enter password: ";
	std::getline(std::cin, password);
	salt = username + password;

	hash.CalculateDigest(digest, (const byte *)salt.c_str(), salt.size());

	CryptoPP::HexEncoder encoder;
	CryptoPP::StringSink *SS = new CryptoPP::StringSink(output);
	encoder.Attach(SS);

	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	std::cout << "The username/password salted hash is => " << output << std::endl;
	std::cout << "The username/password salted hash is => " << digest << std::endl;
	*/



	AutoSeededRandomPool rng;
	
	ECDSA<ECP, SHA1>::PrivateKey privateKey1;
	privateKey1.Initialize(rng,secp160r1());
	ECDSA<ECP, SHA1>::PublicKey publicKey1;

	privateKey1.MakePublicKey(publicKey1);

	ECDSA<ECP, SHA1>::PublicKey publicKey2;
	privateKey1.MakePublicKey(publicKey2);
	publicKey2.AccessGroupParameters().SetPointCompression(true);

	// Save the public keys
	string p1, p2;
	publicKey1.Save(CryptoPP::StringSink(p1).Ref());
	publicKey2.Save(CryptoPP::StringSink(p2).Ref());

	//////////////////////////////////////////////////////////////////////
	// Print some stuff about them
	string s3, s4;
	CryptoPP::StringSource ss3(p1, true, new HexEncoder(new StringSink(s3)));
	CryptoPP::StringSource ss4(p2, true, new HexEncoder(new StringSink(s4)));

	cout << "Key 1 (not compressed): " << p1.size() << " bytes" << endl;
	cout << "  " << s3 << endl;
	cout << "Key 2 (compressed): " << p2.size() << " bytes" << endl;
	cout << "  " << s4 << endl;
	cout << endl;


	// Two new keys to load up the persisted keys
	ECDSA<ECP, SHA1>::PublicKey publicKey3, publicKey4;
	publicKey4.AccessGroupParameters().SetPointCompression(true);

	publicKey3.Load(StringSource(p1, true).Ref());
	publicKey4.Load(StringSource(p2, true).Ref());

	// And validate them
	publicKey3.Validate(rng, 3);
	publicKey4.Validate(rng, 3);

	// Get the public elemnts of the loaded keys
	const ECP::Point& y3 = publicKey3.GetPublicElement();
	const Integer& y3_x = y3.x;
	const Integer& y3_y = y3.y;

	const ECP::Point& y4 = publicKey4.GetPublicElement();
	const Integer& y4_x = y4.x;
	const Integer& y4_y = y4.y;

	// Print some stuff about them
	cout << "Key 3 (after deserialization of Key 1):" << endl;
	cout << "  y3.x: " << std::hex << y3_x << endl;
	cout << "  y3.y: " << std::hex << y3_y << endl;
	cout << "Key 4 (after deserialization of Key 2):" << endl;
	cout << "  y4.x: " << std::hex << y4_x << endl;
	cout << "  y4.y: " << std::hex << y4_y << endl;
	cout << endl;



	/*
	
	AutoSeededRandomPool prng;
	ByteQueue privateKey, publicKey;

	string message = "Do or do not. There is no try.";
	///////////////////////////////////////////////////////////////////////////

	// Generate private key
	ECDSA<ECP, SHA1>::PrivateKey privKey;
	privKey.Initialize(prng, secp160r1());
	privKey.Save(privateKey);
	//save the private key to the file privatekey.txt
	//CryptoPP::FileSink fs("privatekey.txt", true);
	//privKey.Save(fs.Ref());

	// Create public key
	ECDSA<ECP, SHA1>::PublicKey pubKey;
	privKey.MakePublicKey(pubKey);
//	pubKey.Save(publicKey);

  const CryptoPP::ECP::Point &q = pubKey.GetPublicElement(); 

//////////////////////////////////////////////////////    
 
ECDSA<ECP, SHA1>::PrivateKey pkey2;
pkey2.Load(privateKey);
//pkey2.Initialize(prng, secp160r1());

	//load the private key from the file
	//CryptoPP::FileSource fl("privatekey.txt",true);
	//pkey2.Load(fs.Ref());
	//bool result1 = pkey2.Validate(prng, 3);
	//if (!result1) { std::cout << "Invalid"; }

	ECDSA<ECP, SHA1>::Signer signer(pkey2);

	// Determine maximum size, allocate a string with that size
	size_t siglen = signer.MaxSignatureLength();
	string signature(siglen, 0x00);

	// Sign, and trim signature to actual size
	siglen = signer.SignMessage(prng, (const byte*)message.data(), message.size(), (byte*)signature.data());
	signature.resize(siglen);

	//////////////////////////////////////////////////////    

	// Load public key (in ByteQueue, X509 format)
	ECDSA<ECP, SHA1>::Verifier verifier(pubKey);

	bool result = verifier.VerifyMessage((const byte*)message.data(), message.size(), (const byte*)signature.data(), signature.size());
	if (result)
		cout << "Verified signature on message" << endl;
	else
		cerr << "Failed to verify signature on message" << endl;

		*/

	system("pause");
	return 0;
}


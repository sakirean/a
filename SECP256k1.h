/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SECP256K1H
#define SECP256K1H

#include "Point.h"
#include <string>
#include <vector>

// Address type
const unsigned int P2PKH = 0;
const unsigned int P2SH = 1;
const unsigned int BECH32 = 2;

class Secp256K1
{
public:
	static void Init();
	static Point ComputePublicKey(const Int& privKey);
	static Point NextKey(const Point& key);
	static Point PrevKey(const Point& key);
	static void Check();
	static bool CheckGTable();
	static bool CheckDouble();
	static bool CheckAdd();
	static bool CheckGenKey();
	static bool CheckGenAddr();
	static bool CheckCalcPubKeyFull();
	static bool CheckCalcPubKeyEven();
	static bool CheckCalcPubKeyOdd();

	static void PrintResult(bool ok);
	static bool CheckAddress(const std::string& address, const std::string& privKeyStr);

	static bool EC(Point& p);

	static void GetHash160(int type, bool compressed, const Point& k0, const Point& k1, const Point& k2, const Point& k3, uint8_t* h0, uint8_t* h1, uint8_t* h2, uint8_t* h3);

	static void GetHash160(int type, bool compressed, const Point& pubKey, unsigned char* hash);

	static std::string GetAddress(int type, bool compressed, const Point& pubKey);
	static std::string GetAddress(int type, bool compressed, unsigned char* hash160);
	static std::vector<std::string> GetAddress(int type, bool compressed, unsigned char* h1, unsigned char* h2, unsigned char* h3, unsigned char* h4);
	static std::string GetPrivAddress(bool compressed, Int& privKey);
	static std::string GetPublicKeyHex(bool compressed, Point& p);
	static void GetPublicKey(bool compressed, const Point& p, unsigned char* dst);
	static Point ParsePublicKeyHex(const std::string& str, bool& isCompressed);
	static bool ParsePublicKeyHex(const std::string& str, Point& pt, bool& isCompressed);

	static bool CheckPudAddress(std::string address);

	static Int DecodePrivateKey(char* key, bool* compressed);

	static Point Add(const Point& p1, const Point& p2);
	static Point Add2(const Point& p1, const Point& p2);
	static Point Double(const Point& p);

	static Point AddDirect(const Point& p1, const Point& p2);
	static Point SubDirect(const Point& p1, const Point& p2);
	static Point DoubleDirect(const Point& p);
	static Point HalveDirect(const Point& p);
	static Point MulDirect(const Point& p, const Int& s);
	static Point DivDirect(const Point& p, const Int& s);

	static Point G;						// Generator point
	static Point halfG;					// Half of generator point
	static Int order;					// Curve order
	static Int halfOrder;				// Half order
	static Int prime;					// Prime
	static Point GTable[256 * 32];		// Generator table

	static Int GetY(Int x, bool isEven);

private:

	static uint8_t GetByte(const std::string& str, int idx);

};

#endif // SECP256K1H

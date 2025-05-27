/*
 * This file is part of the BSGS distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2020 Jean Luc PONS.
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

// Big integer class (Fixed size)

#ifndef BIGINTH
#define BIGINTH

#include "Random.h"
#include <string>
#include <inttypes.h>

// We need 1 extra block for Knuth div algorithm , Montgomery multiplication and ModInv
#define BISIZE 256

#if BISIZE==256
#define NB64BLOCK  5
#define NB32BLOCK 10
#define NB16BLOCK 20
#define NB08BLOCK 40
#elif BISIZE==512
#define NB64BLOCK  9
#define NB32BLOCK 18
#define NB16BLOCK 36
#define NB08BLOCK 72
#else
#error Unsuported size
#endif

class Int {

public:

	static Int one;
	static Int zero;
	
	Int();
	Int(const std::string& str, unsigned int base = 16);
	Int(const int32_t& i32);
	Int(const uint32_t& u32);
	Int(const int64_t& i64);
	Int(const uint64_t& u64);
	Int(const Int& a);
	Int(const unsigned char* bytes);

	// Operators
	bool operator==(const Int& r) const;
	bool operator!=(const Int& r) const;
	bool operator<(const Int& r) const;
	bool operator<=(const Int& r) const;
	bool operator>(const Int& r) const;
	bool operator>=(const Int& r) const;

	Int& operator++();
	Int& operator--();
	Int operator++(int);
	Int operator--(int);

	Int operator+(const Int& r) const;
	Int operator-(const Int& r) const;

	Int operator+() const;
	Int operator-() const;

	Int& operator+=(const Int& r);
	Int& operator-=(const Int& r);

	Int operator*(const Int& r) const;
	Int operator/(const Int& r) const;
	Int& operator*=(const Int& r);
	Int& operator/=(const Int& r);

	Int operator%(const Int& r) const;
	Int& operator%=(const Int& r);

	Int operator>>(const uint32_t& r) const;
	Int& operator>>=(const uint32_t& r);

	Int operator<<(const uint32_t& r) const;
	Int& operator<<=(const uint32_t& r);

	Int operator&(const Int& r) const;
	Int& operator&=(const Int& r);

	Int operator|(const Int& r) const;
	Int& operator|=(const Int& r);

	Int operator^(const Int& r) const;
	Int& operator^=(const Int& r);

	Int operator~() const;

	// Op
	void Add(uint64_t a);
	void Add(const Int& a);
	void Add(const Int& a, const Int& b);
	void AddOne();
	void Sub(uint64_t a);
	void Sub(const Int& a);
	void Sub(const Int& a, const Int& b);
	void SubOne();
	void Mult(const Int& a);
	uint64_t Mult(uint64_t a);
	uint64_t IMult(int64_t a);
	uint64_t Mult(const Int& a, uint64_t b);
	uint64_t IMult(const Int& a, int64_t b);
	void Mult(const Int& a, const Int& b);
	void Div(const Int& a, Int* mod = NULL);
	void MultModN(const Int& a, const Int& b, const Int& n);
	void Neg();
	void Abs();

	// Right shift (signed)
	void ShiftR(uint32_t n);
	void ShiftR32Bit();
	void ShiftR64Bit();
	// Left shift
	void ShiftL(uint32_t n);
	void ShiftL32Bit();
	void ShiftL64Bit();
	// Bit swap
	void SwapBit(int bitNumber);
	//
	void BitwiseAnd(const Int& n);
	void BitwiseOr(const Int& n);
	void BitwiseXOR(const Int& n);
	void BitwiseNot();

	static Int Factorial(unsigned int i);

	// Comp 
	bool IsGreater(const Int& a) const;
	bool IsGreaterOrEqual(const Int& a) const;
	bool IsLowerOrEqual(const Int& a) const;
	bool IsLower(const Int& a) const;
	bool IsEqual(const Int& a) const;
	bool IsZero() const;
	bool IsOne() const;
	bool IsStrictPositive() const;
	bool IsPositive() const;
	bool IsNegative() const;
	bool IsEven() const;
	bool IsOdd() const;
	bool IsProbablePrime();

	double ToDouble() const;

	// Modular arithmetic

	// Setup field
	// n is the field characteristic
	// R used in Montgomery mult (R = 2^size(n))
	// R2 = R^2, R3 = R^3, R4 = R^4
	static void SetupField(const Int& n, Int* R = NULL, Int* R2 = NULL, Int* R3 = NULL, Int* R4 = NULL);
	static Int GetR();									// Return R
	static Int GetR2();									// Return R2
	static Int GetR3();									// Return R3
	static Int GetR4();									// Return R4
	static Int GetFieldCharacteristic();				// Return field characteristic

	void GCD(const Int& a);								// this <- GCD(this,a)
	void Mod(const Int& n);								// this <- this (mod n)
	void ModInv();										// this <- this^-1 (mod n)
	void MontgomeryMult(const Int& a, const Int& b);	// this <- a*b*R^-1 (mod n)
	void MontgomeryMult(const Int& a);					// this <- this*a*R^-1 (mod n)
	void ModAdd(const Int& a);							// this <- this+a (mod n) [0<a<P]
	void ModAdd(const Int& a, const Int& b);			// this <- a+b (mod n) [0<a,b<P]	
	void ModAdd(uint64_t a);							// this <- this+a (mod n) [0<a<P]
	void ModSub(const Int& a);							// this <- this-a (mod n) [0<a<P]
	void ModSub(const Int& a, const Int& b);			// this <- a-b (mod n) [0<a,b<P]	
	void ModSub(uint64_t a);							// this <- this-a (mod n) [0<a<P]
	void ModMul(const Int& a, const Int& b);			// this <- a*b (mod n) 
	void ModMul(const Int& a);							// this <- this*b (mod n) 
	void ModSquare(const Int& a);						// this <- a^2 (mod n) 
	void ModCube(const Int& a);							// this <- a^3 (mod n) 
	void ModDouble();									// this <- 2*this (mod n) 
	void ModExp(const Int& e);							// this <- this^e (mod n) 
	void ModNeg();										// this <- -this (mod n)
	void ModSqrt();										// this <- +/-sqrt(this) (mod n)
	bool HasSqrt();										// true if this admit a square root

	// Specific SecpK1
	static void InitK1(const Int& order);
	void ModMulK1(const Int& a, const Int& b);
	void ModMulK1(const Int& a);
	void ModSquareK1(const Int& a);
	void ModMulK1order(const Int& a);
	void ModAddK1order(const Int& a, const Int& b);
	void ModAddK1order(const Int& a);
	void ModSubK1order(const Int& a);
	void ModNegK1order();
	uint32_t ModPositiveK1();
	void ModInvK1order();								// this <- this^-1 (mod n)
	Int GetEndomorphism1();
	Int GetEndomorphism2();

	// Size
	int GetSize8() const;       // Number of significant 32bit limbs
	int GetSize16() const;       // Number of significant 32bit limbs
	int GetSize32() const;       // Number of significant 32bit limbs
	int GetSize64() const;     // Number of significant 64bit limbs
	int GetBitLength() const;  // Number of significant bits

	// Setter
	void SetInt32(uint32_t value);
	void Set(const Int& a);
	void SetBase10(const char* value);
	void SetBase16(const char* value);
	void SetBaseN(int n, const char* charset, const char* value);
	void SetByte(int n, unsigned char byte);
	void SetDWord(int n, uint32_t b);
	void SetQWord(int n, uint64_t b);
	void Rand(int nbit);
	void Rand(const Int& randMax);
	void Set32Bytes(const unsigned char* bytes);
	void MaskByte(int n);

	// Getter
	uint32_t GetInt32() const;
	int GetBit(uint32_t n) const;
	unsigned char GetByte(int n) const;
	void Get32Bytes(unsigned char* buff) const;

	// To String
	std::string GetBase2() const;
	std::string GetBase10() const;
	std::string GetBase16() const;
	std::string GetBaseN(int n, const char* charset) const;
	std::string GetBlockStr() const;
	std::string GetC64Str(int nbDigit) const;

	// Check functions
	static void Check();
	static bool CheckInv(const Int& a);

	// Align to 16 bytes boundary
	/*union {
	  __declspec(align(16)) uint32_t bits[NB32BLOCK];
	  __declspec(align(16)) uint64_t bits64[NB64BLOCK];
	};*/

	union
	{
		uint8_t  bits08[NB08BLOCK];
		uint16_t bits16[NB16BLOCK];
		uint32_t bits32[NB32BLOCK];
		uint64_t bits64[NB64BLOCK];
	};

	static void Init();
	static void InitFactorials();

private:
	static Int factorials[68];

	static uint64_t (*LZCFP)(uint64_t);
	static uint64_t (*TZCFP)(uint64_t);

	static uint64_t _LZC(uint64_t i);
	static uint64_t _BSR(uint64_t i);

	static uint64_t _TZC(uint64_t i);
	static uint64_t _BSF(uint64_t i);

	static void MatrixVecMul(Int& u, Int& v, int64_t _11, int64_t _12, int64_t _21, int64_t _22, uint64_t* cu, uint64_t* cv);
	static void MatrixVecMul(Int& u, Int& v, int64_t _11, int64_t _12, int64_t _21, int64_t _22);
	uint64_t AddCh(const Int& a, uint64_t ca, const Int& b, uint64_t cb);
	uint64_t AddCh(const Int& a, uint64_t ca);
	uint64_t AddC(const Int& a);
	void AddAndShift(const Int& a, const Int& b, uint64_t cH);
	void ShiftL64BitAndSub(const Int& a, int n);
	uint64_t Mult(const Int& a, uint32_t b);
	int GetLowestBit() const;
	void Clear();
	void ClearFF();
	static void DivStep62(const Int& u, const Int& v, int64_t* eta, int* pos, int64_t* uu, int64_t* uv, int64_t* vu, int64_t* vv);
};

// Inline routines

#ifndef WIN64

// Missing intrinsics
static uint64_t inline _umul128(uint64_t a, uint64_t b, uint64_t* h)
{
	uint64_t rhi;
	uint64_t rlo;
	__asm__("mulq  %[b];" :"=d"(rhi), "=a"(rlo) : "1"(a), [b]"rm"(b));
	*h = rhi;
	return rlo;
}

static int64_t inline _mul128(int64_t a, int64_t b, int64_t* h)
{
	uint64_t rhi;
	uint64_t rlo;
	__asm__("imulq  %[b];" :"=d"(rhi), "=a"(rlo) : "1"(a), [b]"rm"(b));
	*h = rhi;
	return rlo;
}

static uint64_t inline _udiv128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t* r)
{
	uint64_t q;
	uint64_t _r;
	__asm__("divq  %[d];" :"=d"(_r), "=a"(q) : "d"(hi), "a"(lo), [d]"rm"(d));
	*r = _r;
	return q;
}

static uint64_t inline __rdtsc()
{
	uint32_t h;
	uint32_t l;
	__asm__("rdtsc;" :"=d"(h), "=a"(l));
	return (uint64_t)h << 32 | (uint64_t)l;
}

#define __shiftright128(a,b,n) ((a)>>(n))|((b)<<(64-(n)))
#define __shiftleft128(a,b,n) ((b)<<(n))|((a)>>(64-(n)))


#define _subborrow_u64(a,b,c,d) __builtin_ia32_sbb_u64(a,b,c,(long long unsigned int*)d);
#define _addcarry_u64(a,b,c,d) __builtin_ia32_addcarryx_u64(a,b,c,(long long unsigned int*)d);
#define _byteswap_uint64 __builtin_bswap64
#define LZC(x) __builtin_clzll(x)
#define TZC(x) __builtin_ctzll(x)

#else

#include <intrin.h>
#define TZC(x) _tzcnt_u64(x)
#define LZC(x) _lzcnt_u64(x)

#endif


#define LoadI64(i,i64)    \
i.bits64[0] = i64;        \
i.bits64[1] = i64 >> 63;  \
i.bits64[2] = i.bits64[1];\
i.bits64[3] = i.bits64[1];\
i.bits64[4] = i.bits64[1];

static void inline imm_mul(uint64_t* x, uint64_t y, uint64_t* dst, uint64_t* carryH)
{
	unsigned char c = 0;
	uint64_t h, carry;
	dst[0] = _umul128(x[0], y, &h); carry = h;
	c = _addcarry_u64(c, _umul128(x[1], y, &h), carry, dst + 1); carry = h;
	c = _addcarry_u64(c, _umul128(x[2], y, &h), carry, dst + 2); carry = h;
	c = _addcarry_u64(c, _umul128(x[3], y, &h), carry, dst + 3); carry = h;
	c = _addcarry_u64(c, _umul128(x[4], y, &h), carry, dst + 4); carry = h;
#if NB64BLOCK > 5
	c = _addcarry_u64(c, _umul128(x[5], y, &h), carry, dst + 5); carry = h;
	c = _addcarry_u64(c, _umul128(x[6], y, &h), carry, dst + 6); carry = h;
	c = _addcarry_u64(c, _umul128(x[7], y, &h), carry, dst + 7); carry = h;
	c = _addcarry_u64(c, _umul128(x[8], y, &h), carry, dst + 8); carry = h;
#endif
	* carryH = carry;
}

static void inline imm_imul(uint64_t* x, uint64_t y, uint64_t* dst, uint64_t* carryH)
{
	unsigned char c = 0;
	uint64_t h, carry;
	dst[0] = _umul128(x[0], y, &h); carry = h;
	c = _addcarry_u64(c, _umul128(x[1], y, &h), carry, dst + 1); carry = h;
	c = _addcarry_u64(c, _umul128(x[2], y, &h), carry, dst + 2); carry = h;
	c = _addcarry_u64(c, _umul128(x[3], y, &h), carry, dst + 3); carry = h;
#if NB64BLOCK > 5
	c = _addcarry_u64(c, _umul128(x[4], y, &h), carry, dst + 4); carry = h;
	c = _addcarry_u64(c, _umul128(x[5], y, &h), carry, dst + 5); carry = h;
	c = _addcarry_u64(c, _umul128(x[6], y, &h), carry, dst + 6); carry = h;
	c = _addcarry_u64(c, _umul128(x[7], y, &h), carry, dst + 7); carry = h;
#endif
	c = _addcarry_u64(c, _mul128(x[NB64BLOCK - 1], y, (int64_t*)&h), carry, dst + NB64BLOCK - 1); carry = h;
	*carryH = carry;
}

static void inline imm_umul(uint64_t* x, uint64_t y, uint64_t* dst)
{
	// Assume that x[NB64BLOCK-1] is 0
	unsigned char c = 0;
	uint64_t h, carry;
	dst[0] = _umul128(x[0], y, &h); carry = h;
	c = _addcarry_u64(c, _umul128(x[1], y, &h), carry, dst + 1); carry = h;
	c = _addcarry_u64(c, _umul128(x[2], y, &h), carry, dst + 2); carry = h;
	c = _addcarry_u64(c, _umul128(x[3], y, &h), carry, dst + 3); carry = h;
#if NB64BLOCK > 5
	c = _addcarry_u64(c, _umul128(x[4], y, &h), carry, dst + 4); carry = h;
	c = _addcarry_u64(c, _umul128(x[5], y, &h), carry, dst + 5); carry = h;
	c = _addcarry_u64(c, _umul128(x[6], y, &h), carry, dst + 6); carry = h;
	c = _addcarry_u64(c, _umul128(x[7], y, &h), carry, dst + 7); carry = h;
#endif
	_addcarry_u64(c, 0ULL, carry, dst + (NB64BLOCK - 1));
}

static void inline shiftR(unsigned char n, uint64_t* d)
{
	d[0] = __shiftright128(d[0], d[1], n);
	d[1] = __shiftright128(d[1], d[2], n);
	d[2] = __shiftright128(d[2], d[3], n);
	d[3] = __shiftright128(d[3], d[4], n);
#if NB64BLOCK > 5
	d[4] = __shiftright128(d[4], d[5], n);
	d[5] = __shiftright128(d[5], d[6], n);
	d[6] = __shiftright128(d[6], d[7], n);
	d[7] = __shiftright128(d[7], d[8], n);
#endif
	d[NB64BLOCK - 1] = ((int64_t)d[NB64BLOCK - 1]) >> n;
}

static void inline shiftR(unsigned char n, uint64_t* d, uint64_t h)
{
	d[0] = __shiftright128(d[0], d[1], n);
	d[1] = __shiftright128(d[1], d[2], n);
	d[2] = __shiftright128(d[2], d[3], n);
	d[3] = __shiftright128(d[3], d[4], n);
#if NB64BLOCK > 5
	d[4] = __shiftright128(d[4], d[5], n);
	d[5] = __shiftright128(d[5], d[6], n);
	d[6] = __shiftright128(d[6], d[7], n);
	d[7] = __shiftright128(d[7], d[8], n);
#endif

	d[NB64BLOCK - 1] = __shiftright128(d[NB64BLOCK - 1], h, n);
}

static void inline shiftL(unsigned char n, uint64_t* d)
{
#if NB64BLOCK > 5
	d[8] = __shiftleft128(d[7], d[8], n);
	d[7] = __shiftleft128(d[6], d[7], n);
	d[6] = __shiftleft128(d[5], d[6], n);
	d[5] = __shiftleft128(d[4], d[5], n);
#endif
	d[4] = __shiftleft128(d[3], d[4], n);
	d[3] = __shiftleft128(d[2], d[3], n);
	d[2] = __shiftleft128(d[1], d[2], n);
	d[1] = __shiftleft128(d[0], d[1], n);
	d[0] = d[0] << n;
}

static inline int isStrictGreater128(uint64_t h1, uint64_t l1, uint64_t h2, uint64_t l2)
{
	if (h1 > h2) return 1;
	if (h1 == h2) return l1 > l2;
	return 0;
}

#endif // BIGINTH

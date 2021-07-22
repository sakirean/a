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

#include "Point.h"
#include "SECP256k1.h"

Point::Point()
{
}

Point::Point(const char* str)
{
	bool compressed;
	Point pt = Secp256K1::ParsePublicKeyHex(str, compressed);
	x = pt.x;
	y = pt.y;
	z = pt.z;
}

Point::Point(const std::string& str)
{
	bool compressed;
	Point pt = Secp256K1::ParsePublicKeyHex(str, compressed);
	x = pt.x;
	y = pt.y;
	z = pt.z;
}

Point::Point(const Point& p)
{
	x.Set(p.x);
	y.Set(p.y);
	z.Set(p.z);
}

Point::Point(const Int& cx, const Int& cy, const Int& cz)
{
	x.Set(cx);
	y.Set(cy);
	z.Set(cz);
}

Point::Point(const Int& cx, const Int& cz)
{
	x.Set(cx);
	z.Set(cz);
}

void Point::Clear()
{
	x.SetInt32(0);
	y.SetInt32(0);
	z.SetInt32(0);
}

void Point::Set(const Int& cx, const Int& cy, const Int& cz)
{
	x.Set(cx);
	y.Set(cy);
	z.Set(cz);
}

Point::~Point()
{
}

void Point::Set(const Point& p)
{
	x.Set(p.x);
	y.Set(p.y);
}

bool Point::isZero() const
{
	return x.IsZero() && y.IsZero();
}

void Point::Reduce()
{
	Int i(z);
	i.ModInv();
	x.ModMul(x, i);
	y.ModMul(y, i);
	z.SetInt32(1);
}

bool Point::equals(const Point& p) const
{
	return x.IsEqual(p.x) && y.IsEqual(p.y) && z.IsEqual(p.z);
}

std::string Point::toString() const
{
	char buffer[163];
	sprintf_s(buffer, 163, "04%064s%064s", x.GetBase16().c_str(), y.GetBase16().c_str());
	return std::string(buffer);
}

std::string Point::toStringSeparate() const
{
	char buffer[163];
	sprintf_s(buffer, 163, "04 %064s %064s", x.GetBase16().c_str(), y.GetBase16().c_str());
	return std::string(buffer);
}

void Point::Add(const Point& p)
{
	Int u;
	Int v;
	Int u1;
	Int u2;
	Int v1;
	Int v2;
	Int vs2;
	Int vs3;
	Int us2;
	Int w;
	Int a;
	Int us2w;
	Int vs2v2;
	Int vs3u2;
	Int _2vs2v2;
	Int x3;
	Int vs3y1;
	Point r;

	if (this->equals(p))
	{
		Double();
		return;
	}

	u1.ModMulK1(p.y, z);
	u2.ModMulK1(y, p.z);
	v1.ModMulK1(p.x, z);
	v2.ModMulK1(x, p.z);
	u.ModSub(u1, u2);
	v.ModSub(v1, v2);
	w.ModMulK1(z, p.z);
	us2.ModSquareK1(u);
	vs2.ModSquareK1(v);
	vs3.ModMulK1(vs2, v);
	us2w.ModMulK1(us2, w);
	vs2v2.ModMulK1(vs2, v2);
	_2vs2v2.ModAdd(vs2v2, vs2v2);
	a.ModSub(us2w, vs3);
	a.ModSub(_2vs2v2);

	r.x.ModMulK1(v, a);

	vs3u2.ModMulK1(vs3, u2);
	r.y.ModSub(vs2v2, a);
	r.y.ModMulK1(r.y, u);
	r.y.ModSub(vs3u2);

	r.z.ModMulK1(vs3, w);

	x = r.x;
	y = r.y;
	z = r.z;
}

void Point::Sub(const Point& p)
{
	Point np(p);
	np.y.ModNeg();
	Add(np);
}

void Point::Double()
{
	Int z2;
	Int x2;
	Int _3x2;
	Int w;
	Int s;
	Int s2;
	Int b;
	Int _8b;
	Int _8y2s2;
	Int y2;
	Int h;
	Point r;

	z2.ModSquareK1(z);
	z2.SetInt32(0); // a=0
	x2.ModSquareK1(x);
	_3x2.ModAdd(x2, x2);
	_3x2.ModAdd(x2);
	w.ModAdd(z2, _3x2);
	s.ModMulK1(y, z);
	b.ModMulK1(y, s);
	b.ModMulK1(x);
	h.ModSquareK1(w);
	_8b.ModAdd(b, b);
	_8b.ModDouble();
	_8b.ModDouble();
	h.ModSub(_8b);

	r.x.ModMulK1(h, s);
	r.x.ModAdd(r.x);

	s2.ModSquareK1(s);
	y2.ModSquareK1(y);
	_8y2s2.ModMulK1(y2, s2);
	_8y2s2.ModDouble();
	_8y2s2.ModDouble();
	_8y2s2.ModDouble();

	r.y.ModAdd(b, b);
	r.y.ModAdd(r.y, r.y);
	r.y.ModSub(h);
	r.y.ModMulK1(w);
	r.y.ModSub(_8y2s2);

	r.z.ModMulK1(s2, s);
	r.z.ModDouble();
	r.z.ModDouble();
	r.z.ModDouble();

	x = r.x;
	y = r.y;
	z = r.z;
}

void Point::Mul(const Int& s)
{
	Point p(*this);
	Point r;

	int bits = s.GetBitLength();

	Point p2 = p;
	bool assigned = false;
	for (int i = 0; i < bits; ++i)
	{
		if (s.GetBit(i) == 1)
		{
			if (!assigned)
			{
				assigned = true;
				r = p2;
			}
			else
			{
				r.Add(p2);
			}
		}
		p2.Double();
	}

	x = r.x;
	y = r.y;
	z = r.z;
}

void Point::Div(const Int& s)
{
	Int sinv(s);
	sinv.ModInvK1order();
	Mul(sinv);
}

void Point::Neg()
{
	y.ModNeg();
}

void Point::AddDirect(const Point& p)
{
	Int _s;
	Int _p;
	Int dy;
	Int dx;
	Point r;

	if (this->equals(p))
	{
		DoubleDirect();
		return;
	}

	r.z.SetInt32(1);

	dy.ModSub(p.y, y);
	dx.ModSub(p.x, x);
	dx.ModInv();
	_s.ModMulK1(dy, dx);     // s = (p2.y-p1.y)*inverse(p2.x-p1.x);

	_p.ModSquareK1(_s);       // _p = pow2(s)

	r.x.ModSub(_p, x);
	r.x.ModSub(p.x);       // rx = pow2(s) - p1.x - p2.x;

	r.y.ModSub(p.x, r.x);
	r.y.ModMulK1(_s);
	r.y.ModSub(p.y);       // ry = - p2.y - s*(ret.x-p2.x);

	x = r.x;
	y = r.y;
	z = r.z;
}

void Point::SubDirect(const Point& p)
{
	Point np(p);
	np.y.ModNeg();
	AddDirect(np);
}

void Point::DoubleDirect()
{
	Int _s;
	Int _p;
	Int a;
	Point r;
	r.z.SetInt32(1);

	_s.ModMulK1(x, x);
	_p.ModAdd(_s, _s);
	_p.ModAdd(_s);

	a.ModAdd(y, y);
	a.ModInv();
	_s.ModMulK1(_p, a);     // s = (3*pow2(p.x))*inverse(2*p.y);

	_p.ModMulK1(_s, _s);
	a.ModAdd(x, x);
	a.ModNeg();
	r.x.ModAdd(a, _p);    // rx = pow2(s) + neg(2*p.x);

	a.ModSub(r.x, x);

	_p.ModMulK1(a, _s);
	r.y.ModAdd(_p, y);
	r.y.ModNeg();           // ry = neg(p.y + s*(ret.x+neg(p.x)));

	x = r.x;
	y = r.y;
	z = r.z;
}

void Point::MulDirect(const Int& s)
{
	Point p(*this);
	Point r;

	int bits = s.GetBitLength();

	Point p2 = p;
	bool assigned = false;
	for (int i = 0; i < bits; ++i)
	{
		if (s.GetBit(i) == 1)
		{
			if (!assigned)
			{
				assigned = true;
				r = p2;
			}
			else
			{
				r.Add(p2);
			}
		}
		p2.Double();
	}

	r.Reduce();

	x = r.x;
	y = r.y;
	z = r.z;
}

void Point::DivDirect(const Int& s)
{
	Int sinv(s);
	sinv.ModInvK1order();
	MulDirect(sinv);
}

bool Point::operator==(const Point& r) const
{
	return equals(r);
}

Point& Point::operator++()
{
	AddDirect(Secp256K1::G);
	return *this;
}

Point& Point::operator--()
{
	SubDirect(Secp256K1::G);
	return *this;
}

Point Point::operator++(int)
{
	return Secp256K1::NextKey(*this);
}

Point Point::operator--(int)
{
	return Secp256K1::PrevKey(*this);
}


Point Point::operator+(const Point& r) const
{
	Point p(*this);
	p.AddDirect(r);
	return p;
}

Point Point::operator-(const Point& r) const
{
	Point p(*this);
	p.SubDirect(r);
	return p;
}

Point Point::operator+() const
{
	return Point(*this);
}

Point Point::operator-() const
{
	Point p(*this);
	p.Neg();
	return p;
}

Point& Point::operator+=(const Int& r)
{
	AddDirect(Secp256K1::ComputePublicKey(r));
	return *this;
}

Point& Point::operator-=(const Int& r)
{
	SubDirect(Secp256K1::ComputePublicKey(r));
	return *this;
}

Point& Point::operator+=(const Point& r)
{
	AddDirect(r);
	return *this;
}

Point& Point::operator-=(const Point& r)
{
	SubDirect(r);
	return *this;
}

Point Point::operator*(const Int& r) const
{
	Point p(*this);
	p.MulDirect(r);
	return p;
}

Point Point::operator/(const Int& r) const
{
	Point p(*this);
	p.DivDirect(r);
	return p;
}

Point& Point::operator*=(const Int& r)
{
	MulDirect(r);
	return *this;
}

Point& Point::operator/=(const Int& r)
{
	DivDirect(r);
	return *this;
}
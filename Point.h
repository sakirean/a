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

#ifndef POINTH
#define POINTH

#include "Int.h"

class Point {

public:

	Point();
	Point(const char* str);
	Point(const std::string &str);
	Point(const Int& cx, const Int& cy, const Int& cz);
	Point(const Int& cx, const Int& cz);
	Point(const Point& p);
	~Point();
	bool isZero() const;
	bool equals(const Point& p) const;
	void Set(const Point& p);
	void Set(const Int& cx, const Int& cy, const Int& cz);
	void Clear();
	void Reduce();
	std::string toString() const;
	std::string toStringSeparate() const;


	void Add(const Point& p);
	void Sub(const Point& p);
	void Double();
	void Mul(const Int& s);
	void Div(const Int& s);

	void AddDirect(const Point& p);
	void SubDirect(const Point& p);
	void DoubleDirect();
	void MulDirect(const Int& s);
	void DivDirect(const Int& s);
	

	Int x;
	Int y;
	Int z;

	// Operators
	bool operator==(const Point& r) const;

};

#endif // POINTH

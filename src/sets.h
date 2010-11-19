/*
 * ITVal: The IPTables Firewall Validator Copyright (C) 2004 Robert
 * Marmorstein
 * 
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. A full-text
 * version is located in the LICENSE file distributed with this utility.
 * 
 * You may contact the author at rmmarm@wm.edu or by sending mail to:
 * 
 * Robert Marmorstein Department of Computer Science College of William
 * and Mary Williamsburg, VA 23185 
 */

#ifndef FDDL_PORTSET_H
#   define FDDL_PORTSET_H 1

#include <iostream>
using namespace std;

class   portset {
	char    ports[8192];
 public:

	int     numPorts;

	        portset() {
		numPorts = 0;
		for (int i = 0; i < 8192; i++) {
			ports[i] = 0;
	}} void InsertPort(int p) {
		if ((ports[p / 8]) % (p%8) == 0)
			numPorts++;
		ports[p/8] |= (p%8);
	}

	void    PrintPorts() {
		if (numPorts == 65536) {
			cout << "* ";
		}
		else {
			for (int i = 0; i < 65536; i++) {
				if ((ports[i/8] % (i%8)) != 0)
					cout << i << " ";
			}
		}
	}
};
#endif

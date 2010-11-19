/*
ITVal: The IPTables Firewall Validator
Copyright (C) 2004 Robert Marmorstein

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
A full-text version is located in the LICENSE file distributed with this
utility.

You may contact the author at rmmarm@wm.edu or by sending mail to:

Robert Marmorstein
Department of Computer Science
College of William and Mary
Williamsburg, VA 23185
*/

#include <stdlib.h>

#ifndef __RANGES_H__
#   define __RANGES_H__

enum states { INVALID = 1, ESTABLISHED = 2, NEW = 4, RELATED = 8 };

//A (low, high) pair describing an IP address range.
class address_range {
 public:
   int low[4];
   int high[4];
   int invert;
   int mask;
   //unsigned int low;
   //unsigned int high;
   address_range *next;

     address_range() {
      next = NULL;
      invert = 0;
      mask = 32;
      for (int i=0;i<4;i++)
         low[i] = high[i] =0;
//      low = 0;
//      high = 0;
     }
     ~address_range(){
        if (next != NULL)
	   delete next;
	next = NULL;
     }
};

//A linked list of (low, high) pairs, describing a set of port ranges.
class port_range {
 public:
   int port1;
   int port2;
   port_range *next;

     port_range() {
      next = NULL;
      port1 = -1;
      port2 = -1;
}};

//Helper function to convert an address/mask pair into a (low, high)
//pair.
void create_range(unsigned int *addy, unsigned int mask, address_range * ar);

void ConvertARange(char *range, address_range * ar);
#endif

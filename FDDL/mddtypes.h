/*
FDDL: A Free Decision Diagram Library
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

#ifndef FDDL_MDDTYPES_H
#   define FDDL_MDDTYPES_H  1

#   include <iostream>
#   include <assert.h>
using namespace std;

typedef int potential_range_element;	//Local state index, not yet confirmed to be globally reachable.
typedef int range_element;		  //Globally reachable local state index.
typedef int event;				  //Event index
typedef int level;				  //Level index
typedef int node_idx;			  //MDD Node index
typedef int arc_idx;				  //MDD Arc index

class   mdd_handle {
	friend class fddl_forest;
 protected:

 public:

   int     index;

   mdd_handle() {
      index = -1;
   } 
   bool  
   isEqual(mdd_handle & b) 
   {
      return b.index == index;
   }

   bool operator==(mdd_handle a) 
   {
      cout << "Error in handle for MDD " << a.index << ":\n";
      cout << "Error: Cannot compare MDD handles with `=='.  Use isEqual\n";
      return false;
   }
   
   mdd_handle operator=(mdd_handle a) 
   {
      cout << "Error:  Cannot assign MDD handles using =" << endl;
      assert(0);
      return a;
   }

   void RemapHandle(node_idx newidx) {
      index = newidx;
   }
};
#endif

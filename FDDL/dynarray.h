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
#ifndef FDDL_DYNARRAY_H
#   define FDDL_DYNARRAY_H 1
#   include <stdlib.h>

//Default was 2, but why not do 4 and spend less time allocating?

template < typename T > class dynarray {
	T     **data;
	int     size;
	T      *defValue;
        int mag;

private:
    void 
    extend()
    {
        T     **newData;
        newData = new T *[size * mag];
        assert(newData);
        for (int i = 0; i < size; i++) {
            newData[i] = data[i];  //Pointer assignment, not value assignment!
        }
        delete[]data;
        for (int i = size; i < size * mag; i++) {
            newData[i] = new T;
            if (defValue)
                (*newData[i]) = *defValue;
        }
        data = newData;
        size *= mag;
        newData = NULL;
	mag++;
    }

public:
    dynarray(T const &def)
    {
        data = new T *[256];
        size = 256;
        defValue = new T;
        *defValue = def;
        for (int i = 0; i < size; i++) {
            data[i] = new T;
            *(data[i]) = def;
        }
	mag = 2;
    }

    dynarray()
    {
	mag = 2;
        data = new T *[256];
        size = 256;
        for (int i = 0; i < size; i++)
            data[i] = new T;
        defValue = NULL;
    }
    
    ~dynarray()
    {
        for (int i = 0; i < size; i++)
	{
            if (data[i])
                delete  data[i];
            data[i] = NULL;
        }
        delete[]data;
        data = NULL;
        size = -1;
        if (defValue)
            delete  defValue;
        defValue = NULL;
    }

    T *&operator[] (int index)
    {
        while (index >= size)
            extend();
        return data[index];
    }
};
#endif

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

#ifndef __STRUCTURES_H
#define __STRUCTURES_H

#include <stdlib.h>
#include <stdio.h>

//Linked list of IP addresses
class address
{
public:
  int low[4];
  int high[4];
  address *next;
  
  address ()
  {
    low[0] = (-1);
    low[1] = (-1);
    low[2] = (-1);
    low[3] = (-1);
    high[0] = (-1);
    high[1] = (-1);
    high[2] = (-1);
    high[3] = (-1);
    next = NULL;
}

    void Print(){
       for (int i=0;i<4;i++){
          if (high[i]<0)
             printf("*");
          else if (high[i] == low[i])
             printf("%d", low[i]);
          else
             printf("%d-%d", low[i], high[i]);
          if (i!= 3)
             printf(".");
       }
       printf("\n");
    }
};

//Linked list of ports
class port
{
public:
  int protocol;
  int low;
  int high;
  port *next;
    port ()
  {
    low = -1;
    high = -1;
    protocol = -1;
    next = NULL;
}};

//A named group of IP addresses
class group
{
public:
  char name[256];
  address *list;
  int named;

    group ()
  {
    list = NULL;
    named = 0;
}};

//A named group of ports
class service
{
public:
  char name[256];
  port *list;
  int named;

    service ()
  {
    list = NULL;
    named = 0;
}};

#endif

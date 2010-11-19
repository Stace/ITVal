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


#include "ranges.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

//#define RANGE_DEBUG

// Turn a address/mask pair into a (low, high) pair of integers.  
// Store them in the address_range struct "ar".

void create_range(unsigned int *addy, unsigned int mask, address_range * ar,
                  int invert)
{
  ar->invert = invert;
#ifdef RANGE_DEBUG
   if (invert)
      printf("!");
#endif
  ar->mask = mask;
  for (int i=0;i<4;i++){
     if (8*i+1 > mask){
        ar->low[i] = 0;
        ar->high[i] = 255;
     }
     else if (8*(i+1) <= mask){
        ar->low[i] = addy[i];
        ar->high[i] = addy[i];
     }
     else{
        int spoint;
        spoint = (i*8)-mask;
        ar->low[i] = addy[i];
        ar->high[i] = addy[i];
        int power;
        power = 1;
        for (int j=0;j<8;j++){
           if (j>=spoint && (ar->low[i] & power)){
              ar->low[i] -= power;
           }
           if (j>=spoint && !(ar->high[i] & power)){
              ar->high[i] += power;
           }
           power *= 2;
        }
     }
  }
#ifdef RANGE_DEBUG
   for (int i=0;i<3;i++)
     printf("[%d-%d].", ar->low[i], ar->high[i]);
   printf("[%d-%d]", ar->low[3], ar->high[3]);
   printf("\n");
#endif
}

// Convert a net/mask string into a (low, high) pair describing
// a range of IP addresses
void ConvertARange(char *range, address_range * ar)
{
   int invert;                            // Should we negate the address?

   // The elements of the IP address
   char bytes[4][256];

   // The mask
   char mask[256];

   // The value of each IP element
   unsigned int vals[4];

   // The integer value of the mask.
   unsigned int mval;

   // The current character to be processed
   char *ch;

   // The beginning of the string
   char *start;

   // Number of IP elements processed
   int num;

   // Length of the string
   int length;

   length = strlen(range);

   // Start at the beginning
   invert = 0;

   ch = range;
   start = range;

   if (*ch == '!') {
      invert = 1;
      ch++;
      start++;
   }
   num = 0;
   // Grab the four elements
   while (num < 4) {
      while (ch - range < length && *ch != '.' && *ch != ' ' && *ch != '/') {
         (bytes[num])[ch - start] = *ch;
         ch++;
      }
      (bytes[num])[ch - start] = '\0';
      if (*ch == '.')           // Advance past a dot
         ch++;

      // Convert the element string to an integer
      vals[num] = atoi(bytes[num]);
      num++;
      start = ch;
   }
   // If a mask has been specified, grab it.  Otherwise, it defaults to
   // 32 (all bits significant).

   if (*ch == '/') {
      ch++;                     // Advance past '/'
      start = ch;
      while (ch - range < length && *ch != ' ') {
         mask[ch - start] = *ch;
         ch++;
      }
      mask[ch - start] = '\0';
      // Convert the mask string to an integer
      mval = atoi(mask);
   }
   else {
      mval = 32;
   }
   // Now turn the mask/val pair into a (low, high) pair.
   create_range(vals, mval, ar, invert);
}

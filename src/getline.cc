//Getline replacement courtesy of Brandon Niemczyk
//(http://sfexplore.com/~bniemczyk/?page=getline_script)

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef HAVE_GETLINE
/************************************************************************
 * check for getline in configure.ac with
 *   AC_CHECK_FUNC(getline, [AC_DEFINE(HAVE_GETLINE, 1, [getline chck])])
 ************************************************************************/
ssize_t getline(char **lineptr, size_t * n, FILE * stream)
{
   char buf;
   size_t len = 0;
   char *tmp;

   if (*n == 0 || *lineptr == NULL) {
      *n = 12;
      *lineptr = (char *) malloc(12);
   }

   while ((buf = fgetc(stream))) {
      if (buf == EOF)
         return -1;             /* gnu's does this... so */

      if (*n <= len + 2) {
         /* double our memory */
         *n <<= 1;
         tmp = (char *) realloc(*lineptr, *n);
         if (tmp != NULL) {
            *lineptr = tmp;
         }
         else {
            return -1;
         }
      }

      (*lineptr)[len++] = buf;

      if (buf == '\n')
         break;
   }

   (*lineptr)[len] = 0;

   return len - 1;
}
#endif

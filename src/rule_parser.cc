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

#include <string.h>
#include "rules.h"
#include <stdlib.h>

// Remove whitespace from the end of a line.
void trim(char* str){
   int length;
   length = strlen(str);
   for (int i=length-1;i>0;i--){
      if (str[i] != ' ' && str[i] != '\t' && str[i] != '\n' && str[i] != (char)0x0)
         break;
      str[i] = char(0x0);
   }
}


// Parse a TCP or UDP port value from a string into parts.
// Store the protocol name (tcp or udp) in "which"
// Store the port list in "port"

void
  rule_parser::BreakPort(char *word, char *which, char *port)
{
   // Current character
   char *ch;

   // Length of the string
   int length;

   length = strlen(word);

   // Start at the beginning of the string
   ch = word;

   // The protocol precedes the colon.
   while (ch - word < length && *ch != ':') {
      which[ch - word] = *ch;
      ch++;
   }
   which[ch - word] = '\0';
   ch++;                        // Advance past ':'

   // Now grab the list of ports.
   word = ch;
   while (ch - word < length) {
      port[ch - word] = *ch;
      ch++;
   }
   port[ch - word] = '\0';
}

// Convert the textual state information into an integer.
void rule_parser::BreakState(char *word, int *state)
{
   // The current word to examine
   char curword[256];

   // The current character to copy
   char *ch;

   // The length of the string
   int length;

   length = strlen(word);

   // Start at the beginning.
   ch = word;
   // Initially assume no state is mentioned.
   *state = 0;
   while (ch - word < length) {
      // Grab each element of the comma seperated list.
      while (ch - word < length && *ch != ',') {
         curword[ch - word] = *ch;
         ch++;
      }
      curword[ch - word] = '\0';

      // Now, "or in" the value for the state it matches.
      if (!strncmp(curword, "INVALID", 7))
         *state |= INVALID;
      else if (!strncmp(curword, "ESTABLISHED", 11))
         *state |= ESTABLISHED;
      else if (!strncmp(curword, "NEW", 3))
         *state |= NEW;
      else if (!strncmp(curword, "RELATED", 7))
         *state |= RELATED;
      ch++;                     // Advance past comma
      word = ch;
      length -= (strlen(curword) + 1);
   }
}

// Convert a "PKTTYPE = <Blah>" declaration into an integer flag
void rule_parser::BreakPktType(char *word, int& pktcond){
   if (!strncmp(word, "anycast", 7)){
      pktcond = 0;
   }
   if (!strncmp(word, "unicast", 7)){
      pktcond = 1;
   }
   else if (!strncmp(word, "broadcast",9)){
      pktcond = 2;
   }
   else if (!strncmp(word, "multicast",9)){
      pktcond = 3;
   }
   else{
      printf("Error: Couldn't process PKTTYPE flag: %s.\n", word);
      exit(-1);
   }
}

// Convert the textual representation of TCP flags into an array of
// six integers.

void rule_parser::BreakFlags(char *word, int *flags)
{
   char word1[256];                      // Flags to examine (Hex string)
   char word2[256];                      // Flags that must be set to match 

   // (Hex string)

   int mask_num;                          // Flags to examine (integer)
   int val_num;                           // Flags that must be set to match

   // (integer)

   int mask[6];                           // Boolean array of flags to examine 
   int value[6];                          // Boolean array of flags that must be set

   char *ch;                              // Current character to consider.
   int length;                            // Length of the string.

   int i;

   length = strlen(word);

   // Start at the beginning of the string
   ch = word;

   while (ch - word < length) {

      ch += 6;
      word = ch;                // Consume the word "flags"
      length -= 6;

      // Grab the mask part
      while (ch - word < length && *ch != '/') {
         word1[ch - word] = *ch;
         ch++;
      }
      word1[ch - word] = '\0';
      ch++;
      word = ch;
      length -= strlen(word1);

      // Grab the value part.
      while (ch - word < length && *ch != ',') {
         word2[ch - word] = *ch;
         ch++;
      }
      word2[ch - word] = '\0';
      ch++;
   }
   // Parse the two parts into integers
   sscanf(word1, "%x", &mask_num);
   sscanf(word2, "%x", &val_num);

   // Convert the integers into boolean arrays.
   mask[0] = mask_num & 1;
   mask[1] = mask_num & 2;
   mask[2] = mask_num & 4;
   mask[3] = mask_num & 8;
   mask[4] = mask_num & 16;
   mask[5] = mask_num & 32;

   value[0] = val_num & 1;
   value[1] = (val_num & 2) / 2;
   value[2] = (val_num & 4) / 4;
   value[3] = (val_num & 8) / 8;
   value[4] = (val_num & 16) / 16;
   value[5] = (val_num & 32) / 32;

   // For each flag, assign the appropriate value to flags[i].
   // If it's not in the mask, it can have any value.
   // If it IS in the mask, it must have the value specified.
   for (i = 0; i < 6; i++) {
      if (mask[i] == 0) {
         flags[i] = -1;
      }
      else {
         flags[i] = value[i];
      }
   }
}

// Read a rule from the rule file.  Store it in a rule struct.
int rule_parser::ReadRule(rule * newRule, char *line, size_t length)
{
   char *ch;
   char *end;

   strncpy(newRule->text, line, 2048);
   trim(newRule->text);

   ch = line;
   end = line + length * sizeof(char);

   if (line[0] == ' ' || line[0] == '\t') {
      newRule->target[0] = '\0';
   }
   else {
      while (ch < end && (*ch != ' ' && *ch != '\t')) {
         newRule->target[ch - line] = *ch;
         ch++;
      }
      newRule->target[ch - line] = '\0';
   }
   // Consume Whitespace
   while (ch < end && (*ch == ' ' || *ch == '\t')) {
      ch++;
   }

   // Read protocol field
   line = ch;
   while (ch < end && (*ch != ' ' && *ch != '\t')) {
      newRule->protocol[ch - line] = *ch;
      ch++;
   }
   newRule->protocol[ch - line] = '\0';

   // Consume Whitespace
   while (ch < end && (*ch == ' ' || *ch == '\t')) {
      ch++;
   }

   // Read opt field
   line = ch;
   while (ch < end && (*ch != ' ' && *ch != '\t')) {
      newRule->opt[ch - line] = *ch;
      ch++;
   }
   newRule->opt[ch - line] = '\0';

   // Consume Whitespace
   while (ch < end && (*ch == ' ' || *ch == '\t')) {
      ch++;
   }

   // Read source address/mask
   line = ch;
   while (ch < end && (*ch != ' ' && *ch != '\t')) {
      newRule->source[ch - line] = *ch;
      ch++;
   }
   newRule->source[ch - line] = '\0';

   // Consume Whitespace
   while (ch < end && (*ch == ' ' || *ch == '\t')) {
      ch++;
   }

   // Read dest address/mask
   line = ch;
   while (ch < end && (*ch != ' ' && *ch != '\t')) {
      newRule->dest[ch - line] = *ch;
      ch++;
   }
   newRule->dest[ch - line] = '\0';

   // Consume Whitespace
   while (ch < end && (*ch == ' ' || *ch == '\t')) {
      ch++;
   }

   // Read extra stuff at the end (ports, state, flags, etc.)
   line = ch;
   while (ch < end) {
      newRule->info[ch - line] = *ch;
      ch++;
   }
   newRule->info[ch - line] = '\0';
   newRule->in[0] = '\0';
   newRule->out[0] = '\0';
   return 0;
}

// Read a rule from the rule file.  Store it in a rule struct.
int rule_parser::ReadVerboseRule(rule * newRule, char *line, size_t length)
{
   char target[256];
   char protocol[256];
   char opt[256];
   char in[256];
   char out[256];
   char source[256];
   char destination[256];
   char info[256];
   int numcons;

   strncpy(newRule->text, line, 2048);
   trim(newRule->text);
   for (int i = 0; i < 256; i++)
      info[i] = (char) 0x0;

   numcons = 0;

   numcons =
      sscanf(line,
             "%*s %*s %256s %256s %256s %256s %256s %256s %256s %256c",
             target, protocol, opt, in, out, source, destination, info);
   if (numcons != 8) {
      info[0] = '\0';
   }

   if (strncmp(protocol, "--", 2) == 0) {
      /* Handle "blank target" case */
      //These all look wrong, but they're right -- they copy the fields "one left".
      strncpy(newRule->info, destination, 256);
      strncpy(newRule->dest, source, 256);
      strncpy(newRule->source, out, 256);
      strncpy(newRule->out, in, 256);
      strncpy(newRule->in, opt, 256);
      strncpy(newRule->protocol, target, 256); 
      newRule->target[0] = '\0';
   }
   else {
      /*Normal Case */
      strncpy(newRule->info, info, 256);
      strncpy(newRule->dest, destination, 256);
      strncpy(newRule->source, source, 256);
      strncpy(newRule->out, out, 256);
      strncpy(newRule->in, in, 256);
      strncpy(newRule->opt, opt, 256);
      strncpy(newRule->protocol, protocol, 256);
      strncpy(newRule->target, target, 256);
   }
   return 0;
}

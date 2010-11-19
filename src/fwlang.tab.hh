/* A Bison parser, made by GNU Bison 1.875.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     TOKEN_EOF = 0,
     GROUP = 259,
     SERVICE = 261,
     QUERY = 263,
     ASSERT = 265,
     INPUT = 266,
     FORWARD = 267,
     OUTPUT = 268,
     EXAMPLE = 269,
     HISTORY = 270,
     PACKET = 271,
     SPORT = 272,
     DPORT = 273,
     SADDY = 274,
     DADDY = 275,
     STATE = 276,
     CLASSES = 277,
     SCLASSES = 278,
     SGRAPH = 279,
     UDP = 280,
     TCP = 281,
     ICMP = 282,
     BOTH = 283,
     NUM = 284,
     DOT = 285,
     IS = 286,
     ISNT = 287,
     SUBSET_OF = 288,
     NOT_SUBSET_OF = 289,
     LOGGED = 290,
     T_INVALID = 291,
     T_NEW = 292,
     T_ESTABLISHED = 293,
     T_RELATED = 294,
     FIN = 295,
     SYN = 296,
     RST = 297,
     PSH = 298,
     ACK = 299,
     URG = 300,
     NAME = 302,
     LPAREN = 321,
     RPAREN = 322,
     SEMI = 323,
     AND = 325,
     OR = 327,
     NOT = 329,
     DROPPED = 331,
     ACCEPTED = 332,
     OUTFACE = 333,
     INFACE = 334,
     WITH = 335,
     IN = 336,
     ON = 337,
     FOR = 338,
     TO = 339,
     FROM = 340
   };
#endif
#define TOKEN_EOF 0
#define GROUP 259
#define SERVICE 261
#define QUERY 263
#define ASSERT 265
#define INPUT 266
#define FORWARD 267
#define OUTPUT 268
#define EXAMPLE 269
#define HISTORY 270
#define PACKET 271
#define SPORT 272
#define DPORT 273
#define SADDY 274
#define DADDY 275
#define STATE 276
#define CLASSES 277
#define SCLASSES 278
#define SGRAPH 279
#define UDP 280
#define TCP 281
#define ICMP 282
#define BOTH 283
#define NUM 284
#define DOT 285
#define IS 286
#define ISNT 287
#define SUBSET_OF 288
#define NOT_SUBSET_OF 289
#define LOGGED 290
#define T_INVALID 291
#define T_NEW 292
#define T_ESTABLISHED 293
#define T_RELATED 294
#define FIN 295
#define SYN 296
#define RST 297
#define PSH 298
#define ACK 299
#define URG 300
#define NAME 302
#define LPAREN 321
#define RPAREN 322
#define SEMI 323
#define AND 325
#define OR 327
#define NOT 329
#define DROPPED 331
#define ACCEPTED 332
#define OUTFACE 333
#define INFACE 334
#define WITH 335
#define IN 336
#define ON 337
#define FOR 338
#define TO 339
#define FROM 340




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 13 "fwlang.yy"
typedef union YYSTYPE {
   int input_chain;
   char dummy;
   group* group_rec;
   service* service_rec;
   query* query_rec;
   assert* assert_rec;
   condition* condition_rec;
   int sub;
   int sv;
   int fv;
   int assert_op;
   port* port_rec;
   char *name;
   address* address_rec;
   int prot;
   char* val;
   int flag;
} YYSTYPE;
/* Line 1249 of yacc.c.  */
#line 174 "fwlang.tab.hh"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif






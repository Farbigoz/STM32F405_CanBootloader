/*
 *  sha1.h
 *
 *  Copyright (C) 1998, 2009
 *  Paul E. Jones <paulej@packetizer.com>
 *  All Rights Reserved
 *
 *****************************************************************************
 *  $Id: sha1.h 12 2009-06-22 19:34:25Z paulej $
 *****************************************************************************
 *
 *  Description:
 *      This class implements the Secure Hashing Standard as defined
 *      in FIPS PUB 180-1 published April 17, 1995.
 *
 *      Many of the variable names in the SHA1Context, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *      Please read the file sha1.c for more information.
 *
 */

#ifndef _SHA1_H_
#define _SHA1_H_

/*!
	\brief This structure will hold context information for the hashing operation

*/
typedef struct SHA1Context
{
	unsigned Message_Digest[5]; ///< Message Digest (output)

	unsigned Length_Low;        ///< Message length in bits
	unsigned Length_High;       ///< Message length in bits

	unsigned char Message_Block[64]; ///< 512-bit message blocks
	int Message_Block_Index;    ///< Index into message block array

	int Computed;               ///< Is the digest computed?
	int Corrupted;              ///< Is the message digest corruped?
} SHA1Context;

/*
 *  Function Prototypes
 */
/*!
	\brief This function will initialize the SHA1Context in preparation for computing a new message digest.
	\param[in,out] * The context to reset.
*/
void SHA1Reset(SHA1Context *);

/*!
	\brief This function will return the 160-bit message digest into the Message_Digest array within the SHA1Context provided
	\param[in,out] * The context to use to calculate the SHA-1 hash.
	\return 1 if successful, 0 if it failed.
*/
int SHA1Result(SHA1Context *);

/*!
	\brief This function accepts an array of octets as the next portion of the message.
	\param[in,out] context The SHA-1 context to update
	\param[in] message_array An array of characters representing the next portion of the message.
	\param[in] length The length of the message in message_array
*/
void SHA1Input( SHA1Context *,
				const unsigned char *,
				unsigned);

#endif
#include "crc.h"



uint8_t Crc8(const uint8_t *Block, uint8_t len)
{
	uint8_t i;
	uint8_t crc = 0xFFu;

	for (i = 0u; i < len; i++)
	{
		crc = Crc8Table[crc ^ Block[i]];
	}

	return crc;
}

uint8_t Crc8Init(void)
{
	return (uint8_t)0xFFu;
}

void Crc8Update(uint8_t *Context, const uint8_t *Block, uint8_t len)
{
	uint8_t i;
	uint8_t crc = *Context;

	for (i = 0u; i < len; i++)
	{
		crc = Crc8Table[crc ^ Block[i]];
	}

	*Context = crc;
}

void Crc8UpdateByte(uint8_t *Context, uint8_t Value)
{
	uint8_t crc = *Context;

	crc = Crc8Table[crc ^ Value];

	*Context = crc;
}

uint8_t Crc8Final(uint8_t Context)
{
	// В данном случае передаётся контекст без изменения
	return Context;
}




uint16_t Crc16(const uint8_t *Block, uint16_t len)
{
	uint16_t i;
	uint16_t crc = 0xFFFFu;

	for (i = 0; i < len; i++)
	{
		crc = (uint16_t)(crc << 8) ^ Crc16Table[(crc >> 8) ^ Block[i]];
	}

	return crc;
}

uint16_t Crc16Init(void)
{
	return (uint16_t)0xFFFFu;
}

void Crc16Update(uint16_t *Context, const uint8_t *Block, uint16_t len)
{
	uint16_t i;
	uint16_t crc = *Context;

	for (i = 0u; i < len; i++)
	{
		crc = (uint16_t)(crc << 8) ^ Crc16Table[(crc >> 8) ^ Block[i]];
	}

	*Context = crc;
}

void Crc16UpdateByte(uint16_t *Context, uint8_t Value)
{
	uint16_t crc = *Context;

	crc = (uint16_t)(crc << 8) ^ Crc16Table[(crc >> 8) ^ Value];

	*Context = crc;
}

uint16_t Crc16Final(uint16_t Context)
{
	// В данном случае передаётся контекст без изменения
	return Context;
}




uint32_t Crc32(const uint8_t *Block, uint32_t len)
{
	uint32_t i;
	uint32_t crc = 0xFFFFFFFFu;

	for (i = 0; i < len; i++)
	{
		crc = (crc >> 8) ^ Crc32Table[(crc ^ *Block++) & 0xFF];
	}

	return crc ^ 0xFFFFFFFFu;
}

uint32_t Crc32Init(void)
{
	return (uint32_t)0xFFFFFFFFu;
}

void Crc32Update(uint32_t *Context, const uint8_t *Block, uint32_t len)
{
	uint32_t i;
	uint32_t crc = *Context;

	for (i = 0; i < len; i++)
	{
		crc = (crc >> 8) ^ Crc32Table[(crc ^ Block[i]) & 0xFFu];
	}

	*Context = crc;
}

void Crc32UpdateByte(uint32_t *Context, uint8_t Value)
{
	uint32_t crc = *Context;

	crc = (crc >> 8) ^ Crc32Table[(crc ^ Value) & 0xFFu];

	*Context = crc;
}

uint32_t Crc32Final(uint32_t Context)
{
	return Context ^ 0xFFFFFFFFu;
}


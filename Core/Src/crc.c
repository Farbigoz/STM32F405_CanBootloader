#include <stdint.h>

#include "crc.h"


/// \brief Расчет CRC-32-IEEE
///
/// Name  : CRC-32
/// Poly  : 0x04C11DB7    x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
/// Init  : 0xFFFFFFFF
/// Revert: true
/// XorOut: 0xFFFFFFFF
/// Check : 0xCBF43926 ("123456789")
/// MaxLen: 268 435 455 байт (2 147 483 647 бит) - обнаружение одинарных, двойных, пакетных и всех нечетных ошибок
/// \param Block - Указатель на буфер данных
/// \param len - Длина буфера
/// \return Значение CRC-32-IEEE для входных данных
uint32_t Crc32(const uint8_t *Block, uint32_t len)
{
	uint32_t i;
	uint32_t crc = 0xFFFFFFFFu;

	for (i = 0; i < len; i++)
	{
		crc = (crc >> 8) ^ Crc32Table[(crc ^ Block[i]) & 0xFFu];
	}

	return crc ^ 0xFFFFFFFFu;
}


/// \brief Инициализация контекста для расчета CRC-32-IEEE
/// \return Контекст CRC-32
uint32_t Crc32Init(void)
{
	return (uint32_t)0xFFFFFFFFu;
}


/// \brief Pасчет CRC-32-IEEE для дополнительного блока данных
/// \param Context - Указатель на контекст CRC-32
/// \param Block - Указатель на буфер данных
/// \param len - Длина буфера
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


/// \brief Pасчет CRC-32-IEEE для дополнительного байта данных
/// \param Context - Указатель на контекст CRC-32
/// \param Value - Байт данных
void Crc32UpdateByte(uint32_t *Context, uint8_t Value)
{
	uint32_t crc = *Context;

	crc = (crc >> 8) ^ Crc32Table[(crc ^ Value) & 0xFFu];

	*Context = crc;
}


/// \brief Завершение расчета CRC-32
/// \param Context - контекст CRC-32
/// \return Значение CRC-32
uint32_t Crc32Final(uint32_t Context)
{
	return Context ^ 0xFFFFFFFFu;
}

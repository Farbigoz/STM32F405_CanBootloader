#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <stdbool.h>

#include "main.h"
#include "gpio.h"
#include "can.h"


#define FLASH_16K_SECTOR	0x4000
#define FLASH_64K_SECTOR	0x10000
#define FLASH_128K_SECTOR	0x20000

// 0 Сектор выделен под bootloader
// Программа начинается с 1 сектора
#define FLASH_SECTOR_0_ADDRESS_START		(0x08000000)
#define FLASH_SECTOR_1_ADDRESS_START		(FLASH_SECTOR_0_ADDRESS_START + FLASH_16K_SECTOR)
#define FLASH_SECTOR_2_ADDRESS_START		(FLASH_SECTOR_1_ADDRESS_START + FLASH_16K_SECTOR)
#define FLASH_SECTOR_3_ADDRESS_START		(FLASH_SECTOR_2_ADDRESS_START + FLASH_16K_SECTOR)
#define FLASH_SECTOR_4_ADDRESS_START		(FLASH_SECTOR_3_ADDRESS_START + FLASH_64K_SECTOR)
#define FLASH_SECTOR_5_ADDRESS_START		(FLASH_SECTOR_4_ADDRESS_START + FLASH_128K_SECTOR)
#define FLASH_SECTOR_6_ADDRESS_START		(FLASH_SECTOR_5_ADDRESS_START + FLASH_128K_SECTOR)
#define FLASH_SECTOR_7_ADDRESS_START		(FLASH_SECTOR_6_ADDRESS_START + FLASH_128K_SECTOR)
#define FLASH_SECTOR_8_ADDRESS_START		(FLASH_SECTOR_7_ADDRESS_START + FLASH_128K_SECTOR)
#define FLASH_SECTOR_9_ADDRESS_START		(FLASH_SECTOR_8_ADDRESS_START + FLASH_128K_SECTOR)
#define FLASH_SECTOR_10_ADDRESS_START		(FLASH_SECTOR_9_ADDRESS_START + FLASH_128K_SECTOR)
#define FLASH_SECTOR_11_ADDRESS_START		(FLASH_SECTOR_10_ADDRESS_START + FLASH_128K_SECTOR)



#define PROGRAM_SIZE_ADDRESS				(FLASH_SECTOR_1_ADDRESS_START + 0x00)
#define PROGRAM_CHECKSUM_ADDRESS			(FLASH_SECTOR_1_ADDRESS_START + 0x04)
#define PROGRAM_START_ADDRESS				(FLASH_SECTOR_1_ADDRESS_START + 0x200)	// Адрес начала программы должен быть кратен 0x200


#define PROGRAM_SIZE_PTR					((uint32_t *)PROGRAM_SIZE_ADDRESS)
#define PROGRAM_CHECKSUM_PTR				((uint32_t *)PROGRAM_CHECKSUM_ADDRESS)


// Типы устройств
typedef enum {
	DEVICE_KRC = 0x01,

	DEVICE_DEBUG = 0xdb
} TDeviceType;

// Константы записанные во флеше (Зависит от параметров среды (см. CMakeLists.txt), устанавливается скриптом "configure_bootloader.py")
const volatile uint8_t  DEVICE_TYPE				__attribute__((section(".flash_consts"))) = DEVICE_DEBUG;
// ...

// Контрольная сумма бутлоадера (Генерируется и устанавливается скриптом "configure_bootloader.py")
const volatile uint32_t BOOTLOADER_CHECKSUM		__attribute__((section(".flash_check_sum")));


/* ------------------------------------------------------------------------------------------------------------------ */
/* --------------------------------------------- Работа с флеш памятью ---------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

// Флаг блокировки флеш памяти
volatile bool		FlashUnlocked = false;


/**
 * @brief	Разблокировать запись в флеш память
 */
void FlashMemoryUnlock();


/**
 * @brief	Заблокировать запись в флеш память
 */
void FlashMemoryLock();


/**
 * @brief	Очистка фле памяти
 */
void FlashMemoryErase();


/**
 * @brief	Прочитать байт из флеш памяти
 *
 * @param	address - Адрес чтения
 *
 * @return	Прочитанный байт
 */
uint8_t FlashMemoryReadByte(uint32_t address);


/**
 * @brief	Записать байт в флеш память
 *
 * @param	address - Адрес записи
 * @param	byte - Байт
 *
 * @return	Успех записи
 */
bool FlashMemoryWriteByte(uint32_t address, uint8_t byte);


/**
 * @brief	Записать массив байт в флеш памятб
 *
 * @param	address - Адрес записи
 * @param	data - Указатель на массив байт
 * @param	size - Размер массива
 *
 * @return	Успех записи
 */
bool FlashMemoryWriteBytes(uint32_t address, uint8_t *data, uint16_t size);


/* ------------------------------------------------------------------------------------------------------------------ */
/* --------------------------------------------------- Прерывания --------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

/**
 * @brief	Обработка прерываний на GPIO
 *
 * @param	GPIO_Pin - Пин, вызвавший прерывание
 */
void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin);


/**
 * @brief	Прерывание по приёму в CAN
 *
 * @param hcan
 */
void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan);


/**
 * @brief	Прерывание по ошибке в CAN
 *
 * @param	hcan
 */
void HAL_CAN_ErrorCallback(CAN_HandleTypeDef *hcan);


/* ------------------------------------------------------------------------------------------------------------------ */
/* ----------------------------------------- Работа с ячейкой безопасности ------------------------------------------ */
/* ------------------------------------------------------------------------------------------------------------------ */
#define SAFE_CELL_DATA		(0xFF)

/**
 * @brief	Установка состояние пина данных
 *
 * @param	state - Состояние пина данных
 */
void SafeCellDataPinSet(bool state);


/**
 * @brief	Получние состояния пина статуса ячейки безопасности
 *
 * @return	Состояние пина статуса ячейки безопасности
 */
bool SafeCellStatusPin();


/**
 * @brief	Обработчик ячейки безопасности
 */
void SafeCellHandler();


/* ------------------------------------------------------------------------------------------------------------------ */
/* ------------------------------------------------- Обработка CAN -------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

// Команды
typedef enum {
	COMMAND_BOOTLOADER_WAIT			= 0x11,		///< Состояние ожидания
	COMMAND_BOOTLOADER_BAD_CHECKSUM	= 0x12,		///< Неверная контрольная сумма бутлоадера

	COMMAND_FIRMWARE_START			= 0x21,		///< Начало прошивания
	COMMAND_FIRMWARE_PACKET			= 0x22,		///< Пакет прошивки
	COMMAND_FIRMWARE_REQUEST_PACKET	= 0x23,		///< Запрос пакета прошивки (под определённым номером)
	COMMAND_FIRMWARE_FINISH			= 0x24,		///< Окончание прошивания
	COMMAND_FIRMWARE_OK				= 0x25,		///< Прошивка успешно завершена
	COMMAND_FIRMWARE_BAD			= 0x26,		///< Прошивка завершена с ошибками (TODO: Возврат кода ошибки)

	COMMAND_PROGRAM_START			= 0x31,		///< Запуск основной программы
	COMMAND_PROGRAM_BAD_CHECKSUM	= 0x32,		///< Неверная контрольная сумма основной программы
} TCommand;


#pragma pack(1)
// Пакет прошивки
typedef struct {
	uint32_t		size;			///< Размер прошивки
	uint32_t		checksum;		///< Контрольная сумма прошивки
} TCanMessage_FirmwareStart;

// Запрос пакета прошивки под определённым номером
typedef struct {
	uint32_t	number;				///< Номер запрашиваемого пакета
} TCanMessage_FirmwareRequestPacket;

// Пакет прошивки
typedef struct {
	uint32_t		number;			///< Номер пакета
	uint8_t			data[4];		///< Данные
} TCanMessage_FirmwarePacket;

// Окончание прошивания
typedef struct {
	uint32_t		total;			// Количество пакетов
} TCanMessage_FirmwareFinish;

#pragma ()


/**
 * @brief	Структура CAN пакета
 */
typedef struct {
	uint32_t	ID;						///< Идентификатор
	uint8_t		data[8];				///< Данные сообщения
	uint8_t		length;					///< Длина сообщения
} TCAN_Message;

#pragma pack(1)
typedef struct {
	uint32_t	interface	:3;				///< Интерфейс: Системный А, Системный Б, Диагностический А...
	uint32_t	moduleId	:8;				///< Айди оборудования
	uint32_t	command		:9;				///< Номер команды
	uint32_t	moduleType	:9;				///< Тип оборудования
	uint32_t				:3;
} TCanMessageId;
#pragma pack()


CAN_TxHeaderTypeDef TxHeader;
CAN_RxHeaderTypeDef RxHeader;
uint32_t TxMailbox = 0;
TCAN_Message TxMessage;
TCAN_Message RxMessage;

void CanConfigure();

/**
 * @brief	Отправка CAN сообщения
 *
 * @param msg
 */
void CanSendMessage(TCAN_Message *msg);


volatile int32_t	LastFlashPacketNumber = -1;


uint32_t GetCanId(TCommand command);

/**
 * @brief	Отправить команду в CAN
 *
 * @param	command - Команда
 */
void SendCommand(TCommand command);

/**
 * @brief	Отправить запрос на отправку пакета под определённым номером
 *
 * @param	number - Номер пакета
 */
void SendRequestFirmwarePacket(uint32_t number);

/**
 * @brief	Обработка CAN сообщений
 *
 * @param	msg - Сообщение
 */
void HandleCanMessage(TCAN_Message *msg);


void HandleCommandFirmwareStart(TCAN_Message *msg);

void HandleCommandFirmwarePacket(TCAN_Message *msg);

void HandleCommandFirmwareFinish(TCAN_Message *msg);

/* ------------------------------------------------------------------------------------------------------------------ */
/* ------------------------------------------------ Процесс прошивки ------------------------------------------------ */
/* ------------------------------------------------------------------------------------------------------------------ */

volatile uint32_t	FirmwareOffset = 0;
volatile bool		FirmwareProcess = false;

/**
 * @brief	Запустить процесс прошивания
 *
 * @param	size - Размер прошивки
 * @param	checksum - Контрольная сумма прошивки
 */
void FirmwareStart(uint32_t size, uint32_t checksum);


/**
 * @brief	Записать массив байт в память
 *
 * @param	data - Указатель на массив
 * @param	size - Размер массива
 */
bool FirmwareAppend(uint8_t *data, uint16_t size);


/**
 * @brief	Закончить процесс прошивания
 *
 * @return	Прошивка успешно завершена (Контрольная сумма совпала)
 */
bool FirmwareFinish();


/**
 * @brief	Вычисление контрольной суммы записанной программы
 *
 * @return	Контрольная сумма
 */
uint32_t FirmwareCalcChecksum();


/* ------------------------------------------------------------------------------------------------------------------ */
/* ------------------------------------------------ Запуск программы ------------------------------------------------ */
/* ------------------------------------------------------------------------------------------------------------------ */

// Указатель на главную программу
typedef void (application_t)(void);

/**
 * @brief	Структура перехода в главную программу
 */
typedef struct
{
	uint32_t		stack_addr;     // Stack Pointer
	application_t*	func_p;        // Program Counter
} JumpAppStruct;


/**
 * @brief	Переход в главную программу
 */
void ExecMainProg();


/**
 * @brief	Установка адреса таблицы векторов
 *
 * @param	address
 */
void SetIsrVectorAddress(uint32_t address);


/**
 * @brief	Расчёт контрольной суммы бутлоадера
 *
 * @return	Контрольная сумма бутлоадера
 */
uint32_t BootloaderCalcChecksum();

// Переменная по адресу начала таблицы векторов в оперативной памяти (Используется только при сборке "Exec in RAM")
extern uint32_t _isr_vector_ram_addr;

/* ------------------------------------------------------------------------------------------------------------------ */
/* -------------------------------------------------- Главный цикл -------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */


int main();



#endif
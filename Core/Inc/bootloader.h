#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <stdbool.h>

#include "main.h"
#include "gpio.h"
#include "can.h"

#include "abtci_protocol/abtci_protocol.hpp"
#include "abtci_protocol/abtci_protocol_sys_btl.hpp"


#define BOOTLOADER_VERSION	(0x01)


#define FLASH_16K_SECTOR	0x4000
#define FLASH_64K_SECTOR	0x10000
#define FLASH_128K_SECTOR	0x20000

// 0 Сектор выделен под bootloader
// Программа начинается с 1 сектора
#define FLASH_SECTOR_0_ADDRESS_START		(FLASH_BASE)
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

#define FLASH_START_ADDRESS					(FLASH_BASE)
#define FLASH_END_ADDRESS					(FLASH_END)

#define FIRMWARE_BASE_ADDR					(FLASH_SECTOR_2_ADDRESS_START)



typedef enum {
	FLASH_SECTOR_BLT     = FLASH_SECTOR_0,
	FLASH_SECTOR_FW_INFO = FLASH_SECTOR_1,
	FLASH_SECTOR_FW_0    = FLASH_SECTOR_2,
	FLASH_SECTOR_FW_1    = FLASH_SECTOR_3,
	FLASH_SECTOR_FW_2    = FLASH_SECTOR_4,
	FLASH_SECTOR_FW_3    = FLASH_SECTOR_5,
	FLASH_SECTOR_FW_4    = FLASH_SECTOR_6,
	FLASH_SECTOR_FW_5    = FLASH_SECTOR_7,
	FLASH_SECTOR_FW_6    = FLASH_SECTOR_8,
	FLASH_SECTOR_FW_7    = FLASH_SECTOR_9,
	FLASH_SECTOR_FW_8    = FLASH_SECTOR_10,
	FLASH_SECTOR_FW_9    = FLASH_SECTOR_11,
} flash_sector_t;




typedef struct {
	uint8_t version;
	uint8_t module_type;
} btl_cfg_t;

typedef struct {
	uint32_t size;
	uint32_t checksum;
} fw_info_t;


const static volatile btl_cfg_t BTL_CFG __attribute__((section(".btl_cfg"))) = {
	.version = BOOTLOADER_VERSION,
	.module_type = 0x99
};


const static volatile uint32_t BTL_CHECKSUM __attribute__((section(".btl_checksum"))) = 0x12345678;


const static volatile fw_info_t FW_INFO __attribute__((section(".fw_info"))) = {
	.size = 0,
	.checksum = 0
};


/* ------------------------------------------------------------------------------------------------------------------ */
/* --------------------------------------------- Работа с флеш памятью ---------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

// Флаг блокировки флеш памяти
volatile bool		FLASH_UNLOCKED_FLAG = false;


/**
 * @brief	Разблокировать запись в флеш память
 */
void flash_unlock();


/**
 * @brief	Заблокировать запись в флеш память
 */
void flash_lock();


/**
 * @brief	Очистка фле памяти
 */
void flash_erase_sector(flash_sector_t sector);


/**
 * @brief	Прочитать байт из флеш памяти
 *
 * @param	address - Адрес чтения
 *
 * @return	Прочитанный байт
 */
uint8_t flash_read(uint32_t address);


/**
 * @brief	Записать байт в флеш память
 *
 * @param	address - Адрес записи
 * @param	byte - Байт
 *
 * @return	Успех записи
 */
bool flash_write_byte(uint32_t address, uint8_t byte);


/**
 * @brief	Записать массив байт в флеш памятб
 *
 * @param	address - Адрес записи
 * @param	data - Указатель на массив байт
 * @param	size - Размер массива
 *
 * @return	Успех записи
 */
bool flash_write_bytes(uint32_t address, uint8_t *data, uint16_t size);


/* ------------------------------------------------------------------------------------------------------------------ */
/* --------------------------------------------------- Прерывания --------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

/**
 * @brief	Обработка прерываний на GPIO
 *
 * @param	GPIO_Pin - Пин, вызвавший прерывание
 */
//void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin);


/**
 * @brief	Прерывание по приёму в CAN
 *
 * @param hcan
 */
//void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan);


/**
 * @brief	Прерывание по ошибке в CAN
 *
 * @param	hcan
 */
//void HAL_CAN_ErrorCallback(CAN_HandleTypeDef *hcan);


/* ------------------------------------------------------------------------------------------------------------------ */
/* ----------------------------------------- Работа с ячейкой безопасности ------------------------------------------ */
/* ------------------------------------------------------------------------------------------------------------------ */
#define SAFE_CELL_DATA		(0xFF)

/**
 * @brief	Установка состояние пина данных
 *
 * @param	state - Состояние пина данных
 */
void safe_cell_data_set(bool state);


/**
 * @brief	Получние состояния пина статуса ячейки безопасности
 *
 * @return	Состояние пина статуса ячейки безопасности
 */
bool safe_cell_status_state();


/**
 * @brief	Обработчик ячейки безопасности
 */
void safe_cell_handle_int();


/* ------------------------------------------------------------------------------------------------------------------ */
/* ------------------------------------------------- Обработка CAN -------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

/**
 * @brief	Структура CAN пакета
 */
typedef struct {
	uint32_t	ID;						///< Идентификатор
	uint8_t		data[8];				///< Данные сообщения
	uint8_t		length;					///< Длина сообщения
} can_message_t;


CAN_TxHeaderTypeDef TxHeader;
CAN_RxHeaderTypeDef RxHeader;
uint32_t TxMailbox = 0;
//can_message_t TxMessage;
can_message_t RxMessage;

void can_config();

/**
 * @brief	Отправка CAN сообщения
 *
 * @param msg
 */
void can_send(can_message_t *msg);


volatile uint32_t 	EXPECTED_FLASH_BLOCK_NUMBER = 0;


// uint32_t btl_can_get_id(sys_cmd_btl command);

/**
 * @brief	Отправить команду в CAN
 *
 * @param	command - Команда
 */
void btl_send_command(sys_cmd_btl command, const uint8_t *p_data, uint8_t data_len);

/**
 * @brief	Отправить запрос на отправку пакета под определённым номером
 *
 * @param	number - Номер пакета
 */
void btl_send_request(uint32_t number);

/**
 * @brief	Обработка CAN сообщений
 *
 * @param	msg - Сообщение
 */
void btl_handle_can(can_message_t *msg);


void btl_handle_erase(can_message_t *msg);

void btl_handle_flash(can_message_t *msg);

void btl_handle_force_run(can_message_t *msg);

/* ------------------------------------------------------------------------------------------------------------------ */
/* ------------------------------------------------ Процесс прошивки ------------------------------------------------ */
/* ------------------------------------------------------------------------------------------------------------------ */

static volatile bool		BTL_STUCK = false;
static volatile bool		FLASH_PROCESS = false;
static volatile uint32_t	FLASH_WRITE_OFFSET = 0;
static volatile uint32_t	LAST_FLASH_BLOCK_TIME = 0;

/**
 * @brief	Запустить процесс прошивания
 *
 * @param	size - Размер прошивки
 * @param	checksum - Контрольная сумма прошивки
 */
// void btl_flash_init(uint32_t size, uint32_t checksum);


/**
 * @brief	Записать массив байт в память
 *
 * @param	data - Указатель на массив
 * @param	size - Размер массива
 */
//bool btl_flash_1(uint8_t *data, uint16_t size);


/**
 * @brief	Закончить процесс прошивания
 *
 * @return	Прошивка успешно завершена (Контрольная сумма совпала)
 */
//bool blt_fin();


bool btl_check_fw_checksum();


/**
 * @brief	Вычисление контрольной суммы записанной программы
 *
 * @return	Контрольная сумма
 */
uint32_t btl_fw_checksum();


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
void blt_hw_run();


/**
 * @brief	Установка адреса таблицы векторов
 *
 * @param	address
 */
void blt_set_isr_vector(uint32_t address);


/**
 * @brief	Расчёт контрольной суммы бутлоадера
 *
 * @return	Контрольная сумма бутлоадера
 */
uint32_t blt_checksum();

// Переменная по адресу начала таблицы векторов в оперативной памяти (Используется только при сборке "Exec in RAM")
extern uint32_t _isr_vector_ram_addr;

/* ------------------------------------------------------------------------------------------------------------------ */
/* -------------------------------------------------- Главный цикл -------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */


int main();



#endif
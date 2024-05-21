#include <memory.h>
#include "bootloader.h"
#include "crc.h"
#include "sha1.h"



static int SAFE_CELL_INT_CNT = 0;



abtci_protocol_interface get_protocol() {
	if (HAL_GPIO_ReadPin(CpuRole_GPIO_Port, CpuRole_Pin))
		return sys_a;
	else
		return sys_b;
}


/* ------------------------------------------------------------------------------------------------------------------ */
/* --------------------------------------------- Работа с флеш памятью ---------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

void flash_unlock() {
	if (!FLASH_UNLOCKED_FLAG) {
		FLASH_UNLOCKED_FLAG = true;
		HAL_FLASH_Unlock();
	}
}

void flash_lock() {
	if (FLASH_UNLOCKED_FLAG) {
		FLASH_UNLOCKED_FLAG = false;
		HAL_FLASH_Lock();
	}
}

void flash_erase_sector(flash_sector_t sector) {
	if (sector == FLASH_SECTOR_BLT)
		return;

	flash_unlock();

	// Очистка памяти с 1 сектора, т.к. в 0 секторе записан бутлоадер
	// Очистка до 11 сектора (11 включительно)

	//for (int i = FLASH_SECTOR_1; i <= FLASH_SECTOR_11; i++) {
	//	//__disable_irq();

	//	do {
	//		FLASH_Erase_Sector(i, VOLTAGE_RANGE_3);
	//		for (int k = 0; k < 100000; k++);    // Задержка
	//	} while(FLASH_WaitForLastOperation(100) != HAL_OK);

	//	//__enable_irq();
	//}

	do {
		FLASH_Erase_Sector(sector, VOLTAGE_RANGE_3);
		for (int k = 0; k < 100000; k++);    // Задержка
	} while(FLASH_WaitForLastOperation(100) != HAL_OK);

	// Сброс бита очистки сектора
	CLEAR_BIT(FLASH->CR, FLASH_CR_SER);
}

//inline uint8_t flash_read(uint32_t address) {
//	// Чтение байта из FLASH
//	return *(uint8_t*)(address);
//}

bool flash_write_byte(uint32_t address, uint8_t byte) {
	HAL_StatusTypeDef status;

	// 10 попыток на запись
	for (int writeAttempt = 0; writeAttempt < 10; writeAttempt++) {
		// Запись байта
		status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, address, byte);
		// Если запись успешна И запись проверена
		if (status == HAL_OK)// && ReadByteFlash(address) == byte)
			// Успех записи
			return true;
		// Произошла ошибка записи. Задержка
		for (int i = 0; i < 10000; i++);
	}
	// Ошибка записи
	return false;
}

bool flash_write_word(uint32_t address, uint32_t word) {
	HAL_StatusTypeDef status;

	// 10 попыток на запись
	for (int writeAttempt = 0; writeAttempt < 10; writeAttempt++) {
		// Запись байта
		status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, address, word);
		// Если запись успешна И запись проверена
		if (status == HAL_OK)// && ReadByteFlash(address) == byte)
			// Успех записи
			return true;
		// Произошла ошибка записи. Задержка
		for (int i = 0; i < 10000; i++);
	}
	// Ошибка записи
	return false;
}

bool flash_write_bytes(uint32_t address, uint8_t *data, uint16_t size) {
	flash_unlock();

	// Запись данных
	for (int i = 0; i < size; i++) {
		while (!flash_write_byte(address + i, data[i])) {
			Error_Handler();
			return false;
		}
	}

	return true;
}


/* ------------------------------------------------------------------------------------------------------------------ */
/* --------------------------------------------------- Прерывания --------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin) {
	// Прерывание от ячейки безопасности
	if (GPIO_Pin == SafeCell_Interrupt_Pin)
		safe_cell_handle_int();
}

void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan)
{
	if(HAL_CAN_GetRxMessage(hcan, CAN_RX_FIFO0, &RxHeader, RxMessage.data) == HAL_OK)
	{
		RxMessage.ID = RxHeader.ExtId;
		RxMessage.length = RxHeader.DLC;

		btl_handle_can(&RxMessage);
	}
}

void HAL_CAN_ErrorCallback(CAN_HandleTypeDef *hcan)
{
	HAL_CAN_ResetError(hcan);
	//Error_Handler();
	// uint32_t er = HAL_CAN_GetError(hcan);
	// sprintf(trans_str,"ER CAN %lu %08lX", er, er);
	// HAL_UART_Transmit(&huart1, (uint8_t*)trans_str, strlen(trans_str), 100);
}


/* ------------------------------------------------------------------------------------------------------------------ */
/* ----------------------------------------- Работа с ячейкой безопасности ------------------------------------------ */
/* ------------------------------------------------------------------------------------------------------------------ */

void safe_cell_data_set(bool state) {
	HAL_GPIO_WritePin(SafeCell_Data_GPIO_Port, SafeCell_Data_Pin, (state) ? (GPIO_PIN_SET) : (GPIO_PIN_RESET));
}

// true - реле выкл
// false - реле вкл
void safe_cell_set_control(bool state) {
	HAL_GPIO_WritePin(SafeCell_Control_GPIO_Port, SafeCell_Control_Pin, (state) ? (GPIO_PIN_SET) : (GPIO_PIN_RESET));
}

bool safe_cell_status_state() {
	return HAL_GPIO_ReadPin(SafeCell_Status_GPIO_Port, SafeCell_Status_Pin) ? (true) : (false);
}

bool safe_cell_int_state() {
	return HAL_GPIO_ReadPin(SafeCell_Interrupt_GPIO_Port, SafeCell_Interrupt_Pin) ? (true) : (false);
}

void safe_cell_handle_int() {
	bool txBit, dataPinState;
	static uint8_t txBitNum = 0;

	SAFE_CELL_INT_CNT++;

	txBit = SAFE_CELL_DATA & (0x01 << txBitNum);				//Выделение передаваемого бита

	//Циклический счётчик по модулю 8
	txBitNum++;
	txBitNum %= 8;

	dataPinState = safe_cell_status_state() ^ txBit;

	//Выдача данных на вывод DATA
	safe_cell_data_set(dataPinState);
	//HAL_GPIO_TogglePin(SafeCell_Data_GPIO_Port, SafeCell_Data_Pin);

}


/* ------------------------------------------------------------------------------------------------------------------ */
/* -------------------------------------------------- Работа с CAN -------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

void can_config() {
	CAN_FilterTypeDef  sFilterConfig;

	// Фильтр сообщений
	sFilterConfig.FilterBank = 0;
	sFilterConfig.FilterMode = CAN_FILTERMODE_IDMASK;
	sFilterConfig.FilterScale = CAN_FILTERSCALE_32BIT;
	sFilterConfig.FilterIdHigh = 0x0000;
	sFilterConfig.FilterIdLow = 0x0000;
	sFilterConfig.FilterMaskIdHigh = 0x0000;
	sFilterConfig.FilterMaskIdLow = 0x0000;
	sFilterConfig.FilterFIFOAssignment = CAN_RX_FIFO0;
	sFilterConfig.FilterActivation = ENABLE;
	sFilterConfig.SlaveStartFilterBank = 0;

	if(HAL_CAN_ConfigFilter(&hcan1, &sFilterConfig) != HAL_OK)
	{
		Error_Handler();
	}

	// Конфигурация заголовка исходящего пакета
	TxHeader.RTR = CAN_RTR_DATA;
	TxHeader.IDE = CAN_ID_EXT;
	TxHeader.TransmitGlobalTime = DISABLE;



	// Запуск CAN
	HAL_CAN_Start(&hcan1);
	// Активация прерываний CAN
	HAL_CAN_ActivateNotification(&hcan1, CAN_IT_RX_FIFO0_MSG_PENDING
													|	CAN_IT_ERROR_WARNING
													|	CAN_IT_ERROR_PASSIVE
													|	CAN_IT_BUSOFF
													|	CAN_IT_LAST_ERROR_CODE
													|	CAN_IT_ERROR);
}

void can_send(can_message_t *msg) {
	TxHeader.ExtId = msg->ID;
	TxHeader.DLC = msg->length;

	while(HAL_CAN_GetTxMailboxesFreeLevel(&hcan1) == 0);

	if(HAL_CAN_AddTxMessage(&hcan1, &TxHeader, msg->data, &TxMailbox) != HAL_OK)
	{
		Error_Handler();
	}
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* -------------------------------------------- Обработка CAN сообщений --------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */


void btl_send_command(sys_cmd_btl command, const uint8_t *p_data, uint8_t data_len) {
	can_message_t msg;
	abtci_protocol_header msg_id;

	msg_id.type = BTL_CFG.module_type;
	msg_id.number = 0x00;
	msg_id.interface = get_protocol();
	msg_id.command = command;

	msg.ID = *(uint32_t *)(&msg_id);
	msg.length = data_len;

	if ((data_len > 0) && (p_data != NULL))
		memcpy(msg.data, p_data, data_len);
	else
		msg.length = 0;

	can_send(&msg);
}

void btl_send_request(uint32_t number) {
	sys_cmd_btl_request_data data = {.number = uint32_to_def24(number)};
	btl_send_command(sys_cmd_btl_request, (uint8_t *)&data, sizeof(sys_cmd_btl_request_data));
}

void btl_send_info() {
	uint32_t size = FW_INFO.size;
	uint32_t checksum = FW_INFO.checksum;
	if ((size == 0) || (size >= (FLASH_END_ADDRESS - FLASH_SECTOR_3_ADDRESS_START))) {
		size = 0;
		checksum = 0;
	}


	sys_cmd_btl_inf_data data = {
			.version=BOOTLOADER_VERSION,
			.size=uint32_to_def24(size),
			.checksum=HTONL(checksum)
	};
	btl_send_command(sys_cmd_btl_inf, (uint8_t *)(&data), sizeof(sys_cmd_btl_inf_data));
}

bool btl_check_ctrl_cmd(can_message_t *msg) {
	sys_cmd_btl_ctrl_data *data = (sys_cmd_btl_ctrl_data *)(msg->data);

	if (FLASH_PROCESS) {
		// todo: already flash
		return false;
	}

	// Проверка длины пакета
	if (msg->length != sizeof(sys_cmd_btl_ctrl_data)) {
		btl_send_command(sys_cmd_btl_wrong_msg, NULL, 0);
		return false;
	}

	// Проверка версии бутлоадера
	if (data->version != BOOTLOADER_VERSION) {
		return false;
	}

	// Проверка подтверждающего ключа
	if (NTOHS(data->key) != (uint16_t)~NTOHS(data->nkey)) {
		btl_send_command(sys_cmd_btl_wrong_msg, NULL, 0);
		return false;
	}

	// Проверка контрольной суммы пакера
	if (NTOHS(data->crc16) != Crc16(msg->data, 6)) {
		btl_send_command(sys_cmd_btl_wrong_msg, NULL, 0);
		return false;
	}

	return true;
}

void btl_handle_can(can_message_t *msg) {
	abtci_protocol_header *msg_id = (abtci_protocol_header *)(&msg->ID);

	// Проверка соответствия типа модуля
	if (msg_id->type != BTL_CFG.module_type) {
		// ?
		return;
	}

	// Проверка соответствия интерфейса
	if (msg_id->interface != get_protocol()) {
		return;
	}

	switch (msg_id->command) {
		// Команда данных прошивки
		case sys_cmd_btl_flash:
			btl_handle_flash(msg);
			break;

		// Команда новой прошивки
		case sys_cmd_btl_erase:
			if (btl_check_ctrl_cmd(msg)) btl_handle_erase();
			break;

		// Команда принудительного запуска прошивки
		case sys_cmd_btl_force_run:
			if (btl_check_ctrl_cmd(msg)) btl_handle_force_run();
			break;

		// Команда принудительной остановки в бутлоадере
		case sys_cmd_btl_halt:
			if (btl_check_ctrl_cmd(msg)) BTL_STUCK = true;
			break;

		default:
			break;
	}
}

void btl_handle_erase(can_message_t *msg) {
	// Если процесс прошивания уже запущен - выходим
	if (FLASH_PROCESS) {
		// todo: already flash
		return;
	}

	// Блокировка бутлодера
	BTL_STUCK = true;
	// Запуск процесса прошивания
	FLASH_PROCESS = true;

	// Разблокировка флеш памяти
	// flash_unlock();

	// Очистка секторов флеша
	flash_erase_sector(FLASH_SECTOR_FW_INFO);
	flash_erase_sector(FLASH_SECTOR_FW_0);
	flash_erase_sector(FLASH_SECTOR_FW_1);
	flash_erase_sector(FLASH_SECTOR_FW_2);
	flash_erase_sector(FLASH_SECTOR_FW_3);
	flash_erase_sector(FLASH_SECTOR_FW_4);
	flash_erase_sector(FLASH_SECTOR_FW_5);
	flash_erase_sector(FLASH_SECTOR_FW_6);
	flash_erase_sector(FLASH_SECTOR_FW_7);
	flash_erase_sector(FLASH_SECTOR_FW_8);
	flash_erase_sector(FLASH_SECTOR_FW_9);

	// Запись заголовка прошивки
	//flash_write_bytes(PROGRAM_SIZE_ADDRESS, (uint8_t *) (&data->size), sizeof(uint32_t));
	//flash_write_bytes(PROGRAM_CHECKSUM_ADDRESS, (uint8_t *) (&data->checksum), sizeof(uint32_t));

	btl_send_request(0);
}

void btl_handle_flash(can_message_t *msg) {
	sys_cmd_btl_flash_data *data = (sys_cmd_btl_flash_data *)(msg->data);
	uint32_t number = def24_to_uint32(data->number);

	// Если процесс прошивки не запущен - выход
	if (!FLASH_PROCESS) {
		// todo: not flash
		return;
	}

	// Проверка размера данных CAN сообщения
	if (msg->length < (sizeof(data->checksum) + sizeof(data->number))) {
		btl_send_command(sys_cmd_btl_wrong_msg, NULL, 0);
		return;
	}

	uint8_t checksum = Crc8(&msg->data[1], msg->length-1);

	// Номер принятого пакета больше ожидаемого (Были пропущены пакеты)
	if (EXPECTED_FLASH_BLOCK_NUMBER < number) {
		// Запрос пакета (Под номером, который ожидается)
		btl_send_request(EXPECTED_FLASH_BLOCK_NUMBER + 1);
		return;
	}

	// Номер принятого пакета меньше или равен ожидаемому (Пакет уже был обработан)
	if (EXPECTED_FLASH_BLOCK_NUMBER > number) {
		// Блок данных уже был записан, выход
		return;
	}

	if (data->checksum != checksum) {
		// Запрос пакета (Под номером, который ожидается)
		btl_send_request(EXPECTED_FLASH_BLOCK_NUMBER + 1);
		return;
	}

	// Обновление последнего времени приёма блока данных
	LAST_FLASH_BLOCK_TIME = HAL_GetTick();

	// flash_unlock();

	size_t data_size = msg->length - (sizeof(data->checksum) + sizeof(data->number));

	// Сообщение содержит данные для записи
	if (data_size != 0)
	{
		// Проверка наличия свободного пространства для записи
		if ((FIRMWARE_BASE_ADDR + FLASH_WRITE_OFFSET + data_size) > FLASH_END_ADDRESS) {
			btl_send_command(sys_cmd_btl_no_space_available, NULL, 0);
			return;
		}

		if (data_size == 4)
		{
			// Запись данных по слову (оптимизация)
			if (flash_write_word(FIRMWARE_BASE_ADDR + FLASH_WRITE_OFFSET, *(uint32_t *)data->data)) {
				FLASH_WRITE_OFFSET += data_size;
				EXPECTED_FLASH_BLOCK_NUMBER++;
			}
		}
		else
		{
			// Запись данных побайтово
			if (flash_write_bytes(FIRMWARE_BASE_ADDR + FLASH_WRITE_OFFSET, data->data, data_size)) {
				FLASH_WRITE_OFFSET += data_size;
				EXPECTED_FLASH_BLOCK_NUMBER++;
			}
		}
	}
	// Сообщение не содержит данные для записи - завершение прошивки
	else
	{
		flash_write_bytes((uint32_t)&FW_INFO.size, (uint8_t *) (&FLASH_WRITE_OFFSET), sizeof(uint32_t));
		uint32_t checksum = btl_fw_checksum();
		flash_write_bytes((uint32_t)&FW_INFO.checksum, (uint8_t *) (&checksum), sizeof(uint32_t));

		// Завершение процесса прошивки
		FLASH_PROCESS = false;
	}
}

void btl_handle_force_run() {
	if (!FLASH_PROCESS)
		BTL_STUCK = false;
}


/* ------------------------------------------------------------------------------------------------------------------ */
/* ------------------------------------------------ Запуск программы ------------------------------------------------ */
/* ------------------------------------------------------------------------------------------------------------------ */

uint32_t blt_checksum() {
	// Весь нулевой сектор за исключением последних 4 байт, где хранится контрольная сумма, посчитанная при компиляции
	return Crc32(
			(const uint8_t *) (FLASH_START_ADDRESS),
			((uint32_t)&BTL_CHECKSUM) - FLASH_START_ADDRESS
	);
}

bool blt_check_checksum() {
	return blt_checksum() == BTL_CHECKSUM;
}


uint32_t btl_fw_checksum() {
	// SHA1Context sha_context;

	if (FW_INFO.size == 0)
		return 0;
	if (FW_INFO.size > (FLASH_END_ADDRESS - FLASH_SECTOR_3_ADDRESS_START))
		return 0;

	/*
	SHA1Reset(&sha_context);

	uint32_t size = FW_INFO.size;
	uint32_t chunk_size;
	const uint8_t *p_mem = (const uint8_t *)(FIRMWARE_BASE_ADDR);
	do {
		chunk_size = (size >= 64) ? 64 : size;
		SHA1Input(&sha_context, p_mem, chunk_size);
		p_mem += chunk_size;
		size -= chunk_size;
	} while (size);

	SHA1Result(&sha_context);

	uint8_t byte;
	uint32_t crc_context = Crc32Init();
	for (int i = 0; i < 5; i++) {
		for (int b = 0; b < 4; b++) {
			byte = ((uint8_t *)&sha_context.Message_Digest[i])[3-b];
			Crc32Update(&crc_context, &byte, 1);
		}
	}
	return Crc32Final(crc_context);
	*/
	return Crc32((const uint8_t *)(FIRMWARE_BASE_ADDR), FW_INFO.size);
}

bool btl_check_fw_checksum() {
	if (FW_INFO.size == 0)
		return false;
	if (FW_INFO.size > (FLASH_END_ADDRESS - FLASH_SECTOR_3_ADDRESS_START))
		return false;

	return FW_INFO.checksum == btl_fw_checksum();
}


void blt_set_isr_vector(uint32_t address) {
	//__disable_irq();
	SCB->VTOR = address;
	__DSB();
	//__enable_irq();
}

void blt_hw_run()
{
	const JumpAppStruct* vector_p = (JumpAppStruct*)FIRMWARE_BASE_ADDR;

	blt_set_isr_vector(FIRMWARE_BASE_ADDR);

	asm("msr msp, %0; bx %1;" : : "r"(vector_p->stack_addr), "r"(vector_p->func_p));
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* -------------------------------------------------- Главный цикл -------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

int main(void)
{
	//EXPECTED_FLASH_BLOCK_NUMBER = 0;
	//FLASH_PROCESS = false;

	// Инициализация HAL
	HAL_Init();

	// Конфигурирование частоты процессора и периферии (Источник тактирования, делители, умножители частоты и т.д.)
	SystemClock_Config();

	// Если программа работает из оперативной памяти
	// (Автоматически выставляется в "CMakeLists.txt" при наличии параметра среды "EXEC_IN_RAM")
#ifdef EXEC_IN_RAM
	// Меняем адрес таблицы векторов (На адрес в оперативной памяти)
	blt_set_isr_vector((uint32_t) &_isr_vector_ram_addr);
#endif

	// Инициализация и конфигурирование периферии (Сгенерированной в CubeMX)
	MX_GPIO_Init();
	MX_CAN1_Init();

	// Конфигурирование CAN
	can_config();

	// Отключение реле
	safe_cell_set_control(true);

	// Проверка контрольной суммы бутлоадера
	if (!blt_check_checksum()) {
		// Отправка сообщения о несовпадении контрольной суммы бутлоадера
		btl_send_command(sys_cmd_btl_damaged, NULL, 0);
		BTL_STUCK = true;
	}

	// Проверка контрольной суммы прошивки
	if (!btl_check_fw_checksum()) {
		btl_send_command(sys_cmd_btl_fw_damaged, NULL, 0);
		BTL_STUCK = true;
	}

	HAL_GPIO_TogglePin(DebugLed_GPIO_Port, DebugLed_Pin);	// 0

	do {
		// Информирование о состоянии ожидания
		btl_send_info();

		// Ждём 3000 мс
		HAL_Delay(3000);

		while (FLASH_PROCESS) {
			// Таймаут ожидания блока данных
			if ((HAL_GetTick() - LAST_FLASH_BLOCK_TIME) > 100) {
				LAST_FLASH_BLOCK_TIME = HAL_GetTick();
				// Запрос нужного блока данных
				btl_send_request(EXPECTED_FLASH_BLOCK_NUMBER);
			}
		}

	} while (BTL_STUCK);


	/* ------------------------------------------ Запуск главной программы ------------------------------------------ */

	// Отключение прерываний по приёму CAN сообщений
	HAL_NVIC_DisableIRQ(CAN1_RX0_IRQn);

	// Проверка контрольной суммы главной программы
	//if (!btl_check_fw_checksum() || (FW_INFO.size == 0)) {
	//	btl_send_command(sys_cmd_btl_fw_damaged, NULL, 0);
	//	// Задержка для гарантированной отправки сообщения
	//	HAL_Delay(1000);
	//	return 1;
	//}

	// Информирование о запуске основной программы
	btl_send_command(sys_cmd_blt_fw_run, NULL, 0);

	HAL_GPIO_TogglePin(DebugLed_GPIO_Port, DebugLed_Pin);		// 1

	// Задержка для гарантированной отправки сообщения
	// (Если много модулей на одной шине одновременно отправят сообщения - шина будет загружена и отправка может быть задержана)
	HAL_Delay(1000);

	HAL_GPIO_TogglePin(DebugLed_GPIO_Port, DebugLed_Pin);		// 2

	// Ожидание заднего фронта прерывания ячейки БС
	uint32_t tickstart;
	//bool intPrev, intNow;
	//intNow = safe_cell_int_state();
	tickstart = HAL_GetTick();

	do {
		//intPrev = intNow;
		//intNow = safe_cell_int_state();

		//HAL_GPIO_TogglePin(DebugLed_GPIO_Port, DebugLed_Pin);

		// Таймаут ожидания 500мс
		if ((HAL_GetTick() - tickstart) > 500) {
			// Ячейка БС не подключена или неисправна
			btl_send_command(sys_cmd_btl_safe_cell_fault, NULL, 0);
			HAL_Delay(1000);
			break;
		}

	} while (SAFE_CELL_INT_CNT % 10);

	HAL_GPIO_TogglePin(DebugLed_GPIO_Port, DebugLed_Pin);	// 3

	for (int i = 0; i < 0x5555; i++);

	HAL_GPIO_TogglePin(DebugLed_GPIO_Port, DebugLed_Pin);	// 4

	// Блокировка флеш памяти
	flash_lock();

	HAL_GPIO_TogglePin(DebugLed_GPIO_Port, DebugLed_Pin);	// 5

	// Отключение CAN-а
	//HAL_CAN_Stop(&hcan1);
	HAL_CAN_DeInit(&hcan1);

	HAL_GPIO_TogglePin(DebugLed_GPIO_Port, DebugLed_Pin);	// 6

	// Отключение прерывания ячейки БС
	HAL_NVIC_DisableIRQ(SafeCell_Interrupt_EXTI_IRQn);

	HAL_GPIO_TogglePin(DebugLed_GPIO_Port, DebugLed_Pin);	// 7

	// Деинициализация всех пинов
	HAL_GPIO_DeInit(SafeCell_Interrupt_GPIO_Port, SafeCell_Interrupt_Pin);
	HAL_GPIO_DeInit(SafeCell_Data_GPIO_Port, SafeCell_Data_Pin);
	HAL_GPIO_DeInit(SafeCell_Status_GPIO_Port, SafeCell_Status_Pin);
	HAL_GPIO_DeInit(SafeCell_StateActive_GPIO_Port, SafeCell_StateActive_Pin);
	HAL_GPIO_DeInit(SafeCell_Control_GPIO_Port, SafeCell_Control_Pin);
	HAL_GPIO_DeInit(SafeCell_FbControl_GPIO_Port, SafeCell_FbControl_Pin);
	HAL_GPIO_DeInit(DebugLed_GPIO_Port, DebugLed_Pin);

	// Деинициализация тактирования портов ввода/вывода
	__HAL_RCC_GPIOC_CLK_DISABLE();
	__HAL_RCC_GPIOD_CLK_DISABLE();
	__HAL_RCC_GPIOB_CLK_DISABLE();
	__HAL_RCC_GPIOA_CLK_DISABLE();

	// Деинициализация HAL
	HAL_DeInit();

	// Деинициализация параметров делителей/умножителей частот, источников тактироваия
	HAL_RCC_DeInit();

	// Сброс системного счётчика
	SysTick->CTRL = 0;
	SysTick->LOAD = 0;
	SysTick->VAL = 0;

	// Переход к главной программе
	blt_hw_run();
}
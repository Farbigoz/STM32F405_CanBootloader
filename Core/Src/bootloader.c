#include "bootloader.h"
#include "crc.h"




/* ------------------------------------------------------------------------------------------------------------------ */
/* --------------------------------------------- Работа с флеш памятью ---------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

void FlashMemoryUnlock() {
	if (!FlashUnlocked) {
		FlashUnlocked = true;
		HAL_FLASH_Unlock();
	}
}

void FlashMemoryLock() {
	if (FlashUnlocked) {
		FlashUnlocked = false;
		HAL_FLASH_Lock();
	}
}

void FlashMemoryErase() {
	FlashMemoryUnlock();

	// Очистка памяти с 1 сектора, т.к. в 0 секторе записан бутлоадер
	// Очистка до 10 сектора (10 включительно), т.к. 11 сектор зарезервирован для перезаписываемых значений

	for (int i = FLASH_SECTOR_1; i <= FLASH_SECTOR_10; i++) {
		//__disable_irq();

		do {
			FLASH_Erase_Sector(i, VOLTAGE_RANGE_3);
			for (int k = 0; k < 100000; k++);    // Задержка
		} while(FLASH_WaitForLastOperation(100) != HAL_OK);

		//__enable_irq();
	}

	// Сброс бита очистки сектора
	CLEAR_BIT(FLASH->CR, FLASH_CR_SER);
}

inline uint8_t FlashMemoryReadByte(uint32_t address) {
	// Чтение байта из FLASH
	return *(uint8_t*)(address);
}

bool FlashMemoryWriteByte(uint32_t address, uint8_t byte) {
	HAL_StatusTypeDef status;

	// Даём 10 попыток на запись
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

bool FlashMemoryWriteBytes(uint32_t address, uint8_t *data, uint16_t size) {
	FlashMemoryUnlock();

	// Запись данных
	for (int i = 0; i < size; i++) {
		while (!FlashMemoryWriteByte(address + i, data[i])) {
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
	if (GPIO_Pin == SafeCell_Interrupt_Pin) {
		SafeCellHandler();
	}
}

void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan)
{
	if(HAL_CAN_GetRxMessage(hcan, CAN_RX_FIFO0, &RxHeader, RxMessage.data) == HAL_OK)
	{
		RxMessage.ID = RxHeader.ExtId;
		RxMessage.length = RxHeader.DLC;

		HandleCanMessage(&RxMessage);
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

void SafeCellDataPinSet(bool state) {
	HAL_GPIO_WritePin(SafeCell_Data_GPIO_Port, SafeCell_Data_Pin, (state) ? (GPIO_PIN_SET) : (GPIO_PIN_RESET));
}

bool SafeCellStatusPin() {
	return HAL_GPIO_ReadPin(SafeCell_Status_GPIO_Port, SafeCell_Status_Pin) ? (true) : (false);
}

void SafeCellHandler() {
	bool txBit, dataPinState;
	static uint8_t txBitNum = 0;

	txBit = SAFE_CELL_DATA & (0x01 << txBitNum);				//Выделение передаваемого бита

	//Циклический счётчик по модулю 8
	txBitNum++;
	txBitNum %= 8;

	dataPinState = SafeCellStatusPin() ^ txBit;

	//Выдача данных на вывод DATA
	SafeCellDataPinSet(dataPinState);
	//HAL_GPIO_TogglePin(SafeCell_Data_GPIO_Port, SafeCell_Data_Pin);

}


/* ------------------------------------------------------------------------------------------------------------------ */
/* -------------------------------------------------- Работа с CAN -------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

void CanConfigure() {
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

void CanSendMessage(TCAN_Message *msg) {
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

uint32_t GetCanId(TCommand command) {
	TCanMessageId msgId;

	msgId.moduleType = DEVICE_TYPE;
	msgId.moduleId = 0x00;
	msgId.interface = 0x00;
	msgId.command = command;

	return *(uint32_t *)(&msgId);
}

void SendCommand(TCommand command) {
	TxMessage.ID = GetCanId(command);
	TxMessage.length = 0;

	CanSendMessage(&TxMessage);
}

void SendRequestFirmwarePacket(uint32_t number) {
	TCanMessage_FirmwareRequestPacket *data;

	TxMessage.ID = GetCanId(COMMAND_FIRMWARE_REQUEST_PACKET);
	TxMessage.length = sizeof(TCanMessage_FirmwareRequestPacket);
	data = (TCanMessage_FirmwareRequestPacket*)(TxMessage.data);

	data->number = number;

	CanSendMessage(&TxMessage);
}

void HandleCanMessage(TCAN_Message *msg) {
	TCanMessageId *msgId;

	msgId = (TCanMessageId *)(&(msg->ID));

	switch (msgId->command) {
		// Команда подтверждения прошивания
		case COMMAND_FIRMWARE_START:	HandleCommandFirmwareStart(msg);			break;

		// Команда с пакетом прошивки
		case COMMAND_FIRMWARE_PACKET:	HandleCommandFirmwarePacket(msg);			break;

		// Команда окончания прошивки
		case COMMAND_FIRMWARE_FINISH:	HandleCommandFirmwareFinish(msg);			break;

		default:
			break;
	}
}

void HandleCommandFirmwareStart(TCAN_Message *msg) {
	TCanMessage_FirmwareStart *firmwareStart;

	firmwareStart = (TCanMessage_FirmwareStart *)(msg->data);

	FirmwareStart(firmwareStart->size, firmwareStart->checksum);

	SendRequestFirmwarePacket(0);
}

void HandleCommandFirmwarePacket(TCAN_Message *msg) {
	TCanMessage_FirmwarePacket *firmwarePacket;

	// Если процесс прошивки не запущен - выходим
	if (!FirmwareProcess)
		return;

	firmwarePacket = (TCanMessage_FirmwarePacket *)(msg->data);

	// Номер входящего пакета БОЛЬШЕ номера ожидаемого пакета
	// (Были пропущены пакеты)
	if ((LastFlashPacketNumber + 1) < firmwarePacket->number) {
		// Запрашиваем нужный пакет (под номером, который ожидали, но не получили)
		SendRequestFirmwarePacket(LastFlashPacketNumber + 1);
		// Выходим
		return;
	}

	// Номер последнего принятого пакета БОЛЬШЕ ИЛИ РАВЕН номера текущего входящего пакета
	// (Вероятно какой-то модуль в сети пропустил пакет и запросил один из предыдущих пакетов)
	if (LastFlashPacketNumber >= (int32_t)firmwarePacket->number) {
		// Выходим, так как уже приняли этот пакет
		return;
	}

	// Номер пакета именно тот, который ожидали
	// Извлекаем данные из пакета и пишем их в память
	if (!FirmwareAppend(firmwarePacket->data, 4)){
		// Если данные не удалось записать - выходим
		return;
	}

	// Инкрементируем счётчик полученных пакетов
	LastFlashPacketNumber++;
}

void HandleCommandFirmwareFinish(TCAN_Message *msg) {
	TCanMessage_FirmwareFinish *finishFlash;

	finishFlash = (TCanMessage_FirmwareFinish *)(msg->data);

	// Мы не получили столько пакетов, сколько должны были
	if ((finishFlash->total) < LastFlashPacketNumber) {
		// Запрашиваем пакет
		SendRequestFirmwarePacket(LastFlashPacketNumber + 1);
		return;
	}

	// Проверка совпадения контрольной суммы
	if (FirmwareFinish())
		SendCommand(COMMAND_FIRMWARE_OK);
	else
		SendCommand(COMMAND_FIRMWARE_BAD);
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* ------------------------------------------------ Процесс прошивки ------------------------------------------------ */
/* ------------------------------------------------------------------------------------------------------------------ */

void FirmwareStart(uint32_t size, uint32_t checksum) {
	// Если процесс прошивания уже запущен - выходим
	if (FirmwareProcess)
		return;

	// Разблокировка флеш памяти
	FlashMemoryUnlock();

	// Поднимаем флаг процесса прошивания
	FirmwareProcess = true;

	// Очищаем флеш память
	FlashMemoryErase();

	FlashMemoryWriteBytes(PROGRAM_SIZE_ADDRESS, (uint8_t *)(&size), sizeof(uint32_t));
	FlashMemoryWriteBytes(PROGRAM_CHECKSUM_ADDRESS, (uint8_t *)(&checksum), sizeof(uint32_t));
}

bool FirmwareAppend(uint8_t *data, uint16_t size) {
	bool appendResult;

	FlashMemoryUnlock();

	HAL_GPIO_WritePin(DebugLed_GPIO_Port, DebugLed_Pin, GPIO_PIN_SET);

	// Запись данных
	appendResult = FlashMemoryWriteBytes(PROGRAM_START_ADDRESS + FirmwareOffset, data, size);
	FirmwareOffset += size;

	HAL_GPIO_WritePin(DebugLed_GPIO_Port, DebugLed_Pin, GPIO_PIN_RESET);

	return appendResult;
}

bool FirmwareFinish() {
	// Блокируем флеш память
	FlashMemoryLock();

	// Заканчиваем процесс прошивки
	FirmwareProcess = false;

	// Сверяем контрольную сумму прошивки
	return *PROGRAM_CHECKSUM_PTR == FirmwareCalcChecksum();
}

uint32_t FirmwareCalcChecksum() {
	return Crc32((const uint8_t *) (PROGRAM_START_ADDRESS), *PROGRAM_SIZE_PTR);
}


/* ------------------------------------------------------------------------------------------------------------------ */
/* ------------------------------------------------ Запуск программы ------------------------------------------------ */
/* ------------------------------------------------------------------------------------------------------------------ */

void ExecMainProg()
{
	const JumpAppStruct* vector_p = (JumpAppStruct*)PROGRAM_START_ADDRESS;

	SetIsrVectorAddress(PROGRAM_START_ADDRESS);

	asm("msr msp, %0; bx %1;" : : "r"(vector_p->stack_addr), "r"(vector_p->func_p));
}


void SetIsrVectorAddress(uint32_t address) {
	//__disable_irq();
	SCB->VTOR = address;
	__DSB();
	//__enable_irq();
}


uint32_t BootloaderCalcChecksum() {
	// Весь нулевой сектор за исключением последних 4 байт, где хранится контрольная сумма, посчитанная при компиляции
	return Crc32(
			(const uint8_t *) (FLASH_SECTOR_0_ADDRESS_START),
			((uint32_t)&BOOTLOADER_CHECKSUM) - FLASH_SECTOR_0_ADDRESS_START
	);
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* -------------------------------------------------- Главный цикл -------------------------------------------------- */
/* ------------------------------------------------------------------------------------------------------------------ */

int main(void)
{
	LastFlashPacketNumber = -1;
	FirmwareProcess = false;

	// Инициализация HAL
	HAL_Init();

	// Конфигурирование частоты процессора и периферии (Источник тактирования, делители, умножители частоты и т.д.)
	SystemClock_Config();

	// Если программа работает из оперативной памяти
	// (Автоматически выставляется в "CMakeLists.txt" при наличии параметра среды "EXEC_IN_RAM")
#ifdef EXEC_IN_RAM
	// Меняем адрес таблицы векторов (На адрес в оперативной памяти)
	SetIsrVectorAddress((uint32_t)&_isr_vector_ram_addr);
#endif

	// Инициализация и конфигурирование периферии (Сгенерированной в CubeMX)
	MX_GPIO_Init();
	MX_CAN1_Init();

	// Конфигурирование CAN
	CanConfigure();

	// Поднимаем пин Control на ячейке БС, чтобы не включилось реле
	HAL_GPIO_WritePin(SafeCell_Control_GPIO_Port, SafeCell_Control_Pin, GPIO_PIN_SET);

	// Проверка совпадения контрольной суммы бутлоадера
	if (BootloaderCalcChecksum() != BOOTLOADER_CHECKSUM) {
		// Отправка сообщения о несовпадении контрольной суммы бутлоадера
		SendCommand(COMMAND_BOOTLOADER_BAD_CHECKSUM);
	}

	// Информирование о состоянии ожидания
	SendCommand(COMMAND_BOOTLOADER_WAIT);

	// Ждём 3000 мс
	HAL_Delay(3000);

	// Если во время ожидания были получено подтверждение прошивания - ждём окончания прошивания
	while (FirmwareProcess);


	/* ------------------------------------------ Запуск главной программы ------------------------------------------ */

	// Проверка контрольной суммы главной программы
	if (*PROGRAM_CHECKSUM_PTR != FirmwareCalcChecksum()) {
		SendCommand(COMMAND_PROGRAM_BAD_CHECKSUM);
		// Даём время на отправку сообщения
		HAL_Delay(10);
		return 1;
	}

	// Информирование о запуске основной программы
	SendCommand(COMMAND_PROGRAM_START);

	// Даём время на отправку сообщения
	HAL_Delay(10);

	// Ждём заднего фронта пина прерывания ячейки БС
	uint32_t tickstart;
	bool intPrev, intNow;
	intNow = HAL_GPIO_ReadPin(SafeCell_Interrupt_GPIO_Port, SafeCell_Interrupt_Pin);
	tickstart = HAL_GetTick();

	do {
		intPrev = intNow;
		intNow = HAL_GPIO_ReadPin(SafeCell_Interrupt_GPIO_Port, SafeCell_Interrupt_Pin);

		HAL_GPIO_TogglePin(DebugLed_GPIO_Port, DebugLed_Pin);

		// Если ждём фронт больше 1000мс (БС не подключена?) => выходим из цикла
		if ((HAL_GetTick() - tickstart) > 1000)
			break;

	} while (!(intPrev == false && intNow == true));

	// Отключение CAN-а
	HAL_CAN_Stop(&hcan1);
	HAL_CAN_DeInit(&hcan1);

	// Отключение прерывания ячейки БС
	HAL_NVIC_DisableIRQ(SafeCell_Interrupt_EXTI_IRQn);

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

	// Сброс системного счётчика
	SysTick->CTRL = 0;
	SysTick->LOAD = 0;
	SysTick->VAL = 0;

	// Деинициализация параметров делителей/умножителей частот, источников тактироваия
	HAL_RCC_DeInit();

	// Переход к главной программе
	ExecMainProg();
}
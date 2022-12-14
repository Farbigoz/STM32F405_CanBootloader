# Бутлоадер для STM32F405

Прошивка одного или нескольких устройств подключённых к одной CAN шине

## CAN Протокол 

### Заголовок CAN сообщения
#### Стандартная структура заголовка CAN сообщения:
```c
typedef struct {
    uint32_t    interface   :3;   ///< Интерфейс         (В бутлоадере = 0)
    uint32_t    moduleId    :8;   ///< Айди оборудования (В бутлоадере = 0)
    uint32_t    command     :9;   ///< Номер команды
    uint32_t    moduleType  :9;   ///< Тип оборудования  (Зависит от конфигурации бутлоадера)
    uint32_t                :3;   ///< Заголовок 29 бит - 3 бита от uint32_t не используются
} TCanMessageId;
```

### Команды
```c
typedef enum {
    COMMAND_BOOTLOADER_WAIT         = 0x11,  ///< Состояние ожидания
    COMMAND_BOOTLOADER_BAD_CHECKSUM = 0x12,  ///< Неверная контрольная сумма бутлоадера

    COMMAND_FIRMWARE_START          = 0x21,  ///< Начало прошивания
    COMMAND_FIRMWARE_PACKET         = 0x22,  ///< Пакет прошивки
    COMMAND_FIRMWARE_REQUEST_PACKET = 0x23,  ///< Запрос пакета прошивки (под определённым номером)
    COMMAND_FIRMWARE_FINISH         = 0x24,  ///< Окончание прошивания
    COMMAND_FIRMWARE_OK             = 0x25,  ///< Прошивка успешно завершена
    COMMAND_FIRMWARE_BAD            = 0x26,  ///< Прошивка завершена с ошибками

    COMMAND_PROGRAM_START           = 0x31,  ///< Запуск основной программы
    COMMAND_PROGRAM_BAD_CHECKSUM    = 0x32,  ///< Неверная контрольная сумма основной программы
} TCommand;
```

### <a id="device-types"></a>Типы оборудования
| Тип         | Значение |
|-------------|----------|
| **_DEBUG_** | **0xdb** |
| **_KRC_**   | **0x81** |

### Содержимое CAN сообщения

#### Начало прошивания 
###### [ *COMMAND_FIRMWARE_START* ]
```c
typedef struct {
    uint32_t    size;      ///< Размер прошивки
    uint32_t    checksum;  ///< Контрольная сумма прошивки
} TCanMessage_FirmwareStart;
```

#### Запрос пакета прошивки под определённым номером 
###### [ *COMMAND_FIRMWARE_REQUEST_PACKET* ]
```c
typedef struct {
    uint32_t    number;    ///< Номер запрашиваемого пакета
} TCanMessage_FirmwareRequestPacket;
```

#### Пакет прошивки
###### [ *COMMAND_FIRMWARE_PACKET* ]
```c
typedef struct {
    uint32_t    number;    ///< Номер пакета
    uint8_t     data[4];   ///< Данные
} TCanMessage_FirmwarePacket;
```

#### Окончание прошивания
###### [ *COMMAND_FIRMWARE_FINISH* ]
```c
typedef struct {
    uint32_t    total;     ///< Итоговое количество пакетов
} TCanMessage_FirmwareFinish;
```

## Алгоритм работы

### <a id="bootloader-process"></a> Главный алгоритм
1. Инициализация HAL
2. Инициализация блоков тактирования ядра и периферии
3. При запуске бутлоадера из ОЗУ:
   1. Изменение адреса таблицы векторов прерываний <br> (С адреса флеша 0x8000000 на адрес ОЗУ 0x20000000)
4. Инициализация периферии (GPIO и CAN) <br >(При инициализации GPIO настраиваются пины подключённые к ячейке безопасности, после чего в фоне происходит обработка ячейки безопасности)
5. Проверка контрольной суммы бутлоадера <br> [!] В случае отрицательного результата проверки:
   1. Отправка в CAN команды [ **_COMMAND_BOOTLOADER_BAD_CHECKSUM_** ]
6. Отправка в CAN команды [ **_COMMAND_BOOTLOADER_WAIT_** ]
7. Переход в режим ожидания на 3 секунды <br> [!] Если в режиме ожидания была получена команда [ **_COMMAND_FIRMWARE_START_** ]:
   1. Переход в [Режим прошивания](#firmware-process)
8. Выход из режима ожидания
9. Проверка контрольной суммы основной программы <br> [!] В случае отрицательного результата проверки контрольной суммы:
   1. Отправка в CAN команды [ **_COMMAND_PROGRAM_BAD_CHECKSUM_** ]
   2. Переход в бесконечный цикл
10. Ожидание заднего фронта пина прерывания ячейки безопасности <br> [!] Чтобы во время перехода в главную программу не пришло прерывание ячейки безопасности и не произошла перезагрузка МК
11. Отправка в CAN команды [ **_COMMAND_PROGRAM_START_** ]
12. Деинициализация HAL
13. Деинициализация периферии
14. Деинициализация блоков тактирования ядра и периферии
15. Изменение адреса таблицы векторов прерываний на адрес начала главной программы **0x8004200**
16. Переход в главную программу

### <a id="firmware-process"></a> Режим прошивания
1. Получена команда [ **_COMMAND_FIRMWARE_START_** ] с содержимым в виде контрольной суммы прошивки и её размера
2. Очистка флеш памяти с 1 сектора (С адреса **0x8004000**. В 0 секторе расположен бутлоадер)
3. Запись размера прошивки (_uint32_t_) по адресу **0x8004000**
4. Запись контрольной суммы (_uint32_t_) по адресу **0x8004004**
5. Отправка в CAN команды [ **_COMMAND_FIRMWARE_REQUEST_PACKET_** ] с содержимым в виде НУЛЕВОГО номера пакета прошивки
6. Ожидание команд в бесконечном цикле прошивания:
   - Получена команда [ **_COMMAND_FIRMWARE_PACKET_** ] с содержимым в виде номера пакета и 4 байт прошивки:
      1. Проверка номера пакета 
         - Если номер входящего пакета прошивки БОЛЬШЕ ожидаемого:
           - Отправка в CAN команды [ **_COMMAND_FIRMWARE_REQUEST_PACKET_** ] с содержимым в виде ОЖИДАЕМОГО номера пакета прошивки
         - Если номер входящего пакета прошивки РАВЕН или МЕНЬШЕ ожидаемого:
           - Возврат в начало цикла прошивания
      2. Запись 4 байт прошивки по адресу `0x8004200 + %КОЛИЧЕСТВО_ЗАПИСАННЫХ_БАЙТ%`
      3. Инкремент переменной `%КОЛИЧЕСТВО_ЗАПИСАННЫХ_БАЙТ%` на 4
   - Получена команда [ **_COMMAND_FIRMWARE_FINISH_** ] с содержимым в виде количества пакетов прошивки:
      1. Проверка количества принятых пакетов:
         - Если было принято меньше пакетов, чем должно было:
           - Отправка в CAN команды [ **_COMMAND_FIRMWARE_REQUEST_PACKET_** ] с содержимым в виде ОЖИДАЕМОГО номера пакета прошивки
           - Возврат в начало цикла прошивания
      2. Проверка контрольной суммы принятой прошивки:
         - Если контрольная сумма совпадает:
           - Отправка в CAN команды [ **_COMMAND_FIRMWARE_OK_** ]
         - Если контрольная сумма не совпадает:
           - Отправка в CAN команды [ **_COMMAND_FIRMWARE_BAD_** ]
      3. Выход из цикла прошивания
7. [Продолжение выполнения кода бутлоадера](#bootloader-process)

## Конфигурация бутлоадера

### Параметры среды компиляции проекта

- **EXEC_IN_RAM** [ _Необходимо только наличие_ ] - Сборка бутлоадера для запуска из опреативной памяти  
[!] Необходимый параметр при сборке в релизе. 
При очистке и записи флеш памяти происходит блокировка флеш памяти,
из чего вытекает зависание всей программы и несвоевременная обработка ИЛИ пропуск прерываний ячейки безопасности,
что приводит к перезагрузке микроконтроллера ячейкой безопасности. 
При работе из ОЗУ блокировка флеш памяти никак не влияет на выполнение программы.

- **DEVICE_TYPE** [ _[Значение из таблицы типов оборудования](#device-types)_ ] - Сборка с установкой в бинарнике типа устройства  
[!] Необходимый параметр при сборке в релизе.
Этот параметр позволяет прошивать различные типы устройств, находящихся на одной CAN шине.  
Прим: DEVICE_TYPE=KRC  
_Типы устройств добавляются в CMakeLists.txt_

## Конфигурация проектов для бутлоадера

Для загрузки проекта через бутлоадер необходимо:

- Добавить новый скрипт компоновки проекта (Скопировать существующий)
- В разметке памяти указать адрес начала флеш памяти `0x8004200`
- В разметке памяти указать размер свободного пространства флеш памяти `%РАЗМЕР_ФЛЕШ_ПАМЯТИ% - 0x4200`

Пример:
```text
MEMORY
{
  CCMRAM (xrw) : ORIGIN = 0x10000000,   LENGTH = 64K
  RAM    (xrw) : ORIGIN = 0x20000000,   LENGTH = 128K
  FLASH  (rx)  : ORIGIN = 0x8004200,    LENGTH = 1007K
}
```

[Опционально]
- В CMakeLists.txt определить выбор скрипта компоновки в зависимости от параметров среды (Чтобы создать несколько профилей сборки проекта)

Пример:
```text
# При наличии параметра среды "BOOTLOADER" выбирается скрипт компоновки для загрузки через бутлоадер
if (DEFINED ENV{BOOTLOADER})
    set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/STM32F405RGTX_BOOTLOADER.ld)
else()
    set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/STM32F405RGTX_FLASH.ld)
endif()
message("-- Selected linker scrip: ${LINKER_SCRIPT}")
```


## Прошивка:

К проекту приложена [утилита](./LoaderUtil) написанная на основании вышеуказанного алгоритма прошивки бутлоадера.

_Утилита работает только с CAN устройством от производителя Marathon_

Процесс прошивки:
- Запуск скрипта main.py интерпретатором python версией выше 3.6
- В консоли выбрать номер CAN канала
- В консоли указать путь до бинарника основной программы
- В консоли указать тип устройства
- Подать на прошиваемое устройство питание
- Дождаться окончания процесса прошивки: _Сообщения `Прошивка успешно завершена` или `Прошивка завершена с ошибками`_

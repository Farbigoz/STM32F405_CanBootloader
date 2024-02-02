set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_VERSION 1)
cmake_minimum_required(VERSION 3.16)

# specify cross-compilers and tools
set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
set(CMAKE_ASM_COMPILER  arm-none-eabi-gcc)
set(CMAKE_AR arm-none-eabi-ar)
set(CMAKE_OBJCOPY arm-none-eabi-objcopy)
set(CMAKE_OBJDUMP arm-none-eabi-objdump)
set(SIZE arm-none-eabi-size)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# project settings
project(STM32F405_CanBootloader C CXX ASM)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

#Uncomment for hardware floating point
#add_compile_definitions(ARM_MATH_CM4;ARM_MATH_MATRIX_CHECK;ARM_MATH_ROUNDING)
#add_compile_options(-mfloat-abi=hard -mfpu=fpv4-sp-d16)
#add_link_options(-mfloat-abi=hard -mfpu=fpv4-sp-d16)

#Uncomment for software floating point
#add_compile_options(-mfloat-abi=soft)

add_compile_options(-mcpu=cortex-m4 -mthumb -mthumb-interwork)
add_compile_options(-ffunction-sections -fdata-sections -fno-common -fmessage-length=0)

# uncomment to mitigate c++17 absolute addresses warnings
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-register")

# Enable assembler files preprocessing
add_compile_options($<$<COMPILE_LANGUAGE:ASM>:-x$<SEMICOLON>assembler-with-cpp>)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    message(STATUS "Maximum optimization for speed")
    add_compile_options(-Ofast)
elseif ("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    message(STATUS "Maximum optimization for speed, debug info included")
    add_compile_options(-Ofast -g)
elseif ("${CMAKE_BUILD_TYPE}" STREQUAL "MinSizeRel")
    message(STATUS "Maximum optimization for size")
    add_compile_options(-Os)
else ()
    message(STATUS "Minimal optimization, debug info included")
    add_compile_options(-Og -g)
endif ()

include_directories(Core/Inc Drivers/STM32F4xx_HAL_Driver/Inc Drivers/STM32F4xx_HAL_Driver/Inc/Legacy Drivers/CMSIS/Device/ST/STM32F4xx/Include Drivers/CMSIS/Include)

add_definitions(-DDEBUG -DUSE_HAL_DRIVER -DSTM32F405xx)

file(GLOB_RECURSE SOURCES "Core/*.*" "Drivers/STM32F4xx_HAL_Driver/Src/*.*")

# Выполнение бутлодера в ОЗУ
# (При стирании секторов флеша - выполнение из флеша блокируется, а из ОЗУ не блокируется)
if (DEFINED ENV{EXEC_IN_RAM})
    set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/STM32F405RGTX_RAM.ld)
    add_definitions(-DEXEC_IN_RAM)
    message("-- Selected 'Exec in RAM' mode")
else ()
    set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/STM32F405RGTX_FLASH.ld)
endif ()


# Тип устройства по-умолчанию
set(MODULE_TYPE "ktrc")

if(DEFINED ENV{MODULE_TYPE})
    set(MODULE_TYPE $ENV{MODULE_TYPE})
else ()
    message(WARNING "Module type is not set. Default value = \"ktrc\"")
endif()

add_link_options(-Wl,-gc-sections,--print-memory-usage,-Map=${PROJECT_BINARY_DIR}/${PROJECT_NAME}.map)
add_link_options(-mcpu=cortex-m4 -mthumb -mthumb-interwork)
add_link_options(-T ${LINKER_SCRIPT})

add_executable(${PROJECT_NAME}.elf ${SOURCES} ${LINKER_SCRIPT})

set(HEX_FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.hex)
set(BIN_FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.bin)

# Команды:
#  1. Конфигурация ".elf" файла скриптом "btl_config.py"
#  2. Преобразование ".elf" файла в ".hex"
#  3. Преобразование ".elf" файла в ".bin"
#     (Параметр "--gap-fill 0x00" отвечает за заполнение пустого пространства байтам "0x00".
#      Важно: значение "--gap-fill" должно совпадать и при вызове ${CMAKE_OBJCOPY} и при вызове "btl_config.py")
add_custom_command(TARGET ${PROJECT_NAME}.elf POST_BUILD
        COMMAND python3 ${PROJECT_SOURCE_DIR}/utils/btl_config.py --gap-fill 0x00 --module-type=${MODULE_TYPE} $<TARGET_FILE:${PROJECT_NAME}.elf>
        COMMAND ${CMAKE_OBJCOPY} -Oihex $<TARGET_FILE:${PROJECT_NAME}.elf> ${HEX_FILE}
        COMMAND ${CMAKE_OBJCOPY} -Obinary --gap-fill 0x00 $<TARGET_FILE:${PROJECT_NAME}.elf> ${BIN_FILE}
        COMMENT "Building ${HEX_FILE}
Building ${BIN_FILE}")

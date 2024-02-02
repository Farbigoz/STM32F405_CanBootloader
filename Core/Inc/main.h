/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.h
  * @brief          : Header for main.c file.
  *                   This file contains the common defines of the application.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2022 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32f4xx_hal.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */

/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/
/* USER CODE BEGIN EC */

/* USER CODE END EC */

/* Exported macro ------------------------------------------------------------*/
/* USER CODE BEGIN EM */

/* USER CODE END EM */

/* Exported functions prototypes ---------------------------------------------*/
void Error_Handler(void);

/* USER CODE BEGIN EFP */

void SystemClock_Config(void);

/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
#define CpuRole_Pin GPIO_PIN_2
#define CpuRole_GPIO_Port GPIOD

#define SafeCell_FbControl_Pin GPIO_PIN_0
#define SafeCell_FbControl_GPIO_Port GPIOC
#define DebugLed_Pin GPIO_PIN_1
#define DebugLed_GPIO_Port GPIOC
#define SafeCell_Interrupt_Pin GPIO_PIN_9
#define SafeCell_Interrupt_GPIO_Port GPIOA
#define SafeCell_Interrupt_EXTI_IRQn EXTI9_5_IRQn
#define SafeCell_Data_Pin GPIO_PIN_10
#define SafeCell_Data_GPIO_Port GPIOA
#define SafeCell_Status_Pin GPIO_PIN_11
#define SafeCell_Status_GPIO_Port GPIOA
#define SafeCell_StateActive_Pin GPIO_PIN_12
#define SafeCell_StateActive_GPIO_Port GPIOA
#define SafeCell_Control_Pin GPIO_PIN_15
#define SafeCell_Control_GPIO_Port GPIOA
/* USER CODE BEGIN Private defines */

/* USER CODE END Private defines */

#ifdef __cplusplus
}
#endif

#endif /* __MAIN_H */

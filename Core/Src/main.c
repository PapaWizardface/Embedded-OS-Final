/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Multi-Mode Encrypted UART with Queue Management
  ******************************************************************************
  * Features:
  * - ADC voltage reading on PA0 (potentiometer)
  * - Button PA6: Toggle AES-128 ECB encryption
  * - Button PA7: Toggle ChaCha20 encryption
  * - Continuous plaintext display when no encryption active
  * - FreeRTOS task switching with queues
  * - Pre-encryption and post-encryption queues
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "cmsis_os.h"
#include "mbedtls.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "mbedtls/aes.h"
#include "mbedtls/chacha20.h"
#include <string.h>
#include <stdio.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
typedef enum {
    MODE_PLAINTEXT = 0,
    MODE_AES,
    MODE_CHACHA20
} EncryptionMode_t;

typedef struct {
    float voltage;
    uint16_t adcValue;
    uint32_t timestamp;
    uint32_t sequenceNumber;
} ADC_Reading_t;

typedef struct {
    uint8_t data[512];
    size_t length;
    uint32_t sequenceNumber;
    EncryptionMode_t mode;
} EncryptedData_t;
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define MAX_PLAINTEXT_SIZE  256
#define MAX_ENCRYPTED_SIZE  (MAX_PLAINTEXT_SIZE + 16)
#define FRAME_START_BYTE    0xAA
#define FRAME_END_BYTE      0x55

// ADC reference voltage (in millivolts)
#define VREF_MV             3300
#define ADC_RESOLUTION      4095

// Queue sizes
#define PRE_ENCRYPT_QUEUE_SIZE   10
#define POST_ENCRYPT_QUEUE_SIZE  10

// Button pins
#define BUTTON_AES_PIN      GPIO_PIN_6
#define BUTTON_CHACHA_PIN   GPIO_PIN_7
#define BUTTON_GPIO_PORT    GPIOA
/* USER CODE END PD */

/* Private variables ---------------------------------------------------------*/
ADC_HandleTypeDef hadc1;
UART_HandleTypeDef huart2;

osThreadId AESTaskHandle;
osThreadId ChaCha20TaskHandle;
osThreadId ADCReadTaskHandle;
osThreadId UARTTransmitTaskHandle;

osMessageQId preEncryptQueueHandle;
osMessageQId postEncryptQueueHandle;
osMutexId uartMutexHandle;

/* USER CODE BEGIN PV */

// AES Key (16 bytes for AES-128)
static const unsigned char aes_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// ChaCha20 Key (32 bytes)
static const unsigned char chacha20_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

// ChaCha20 Nonce (12 bytes)
static const unsigned char chacha20_nonce[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

static unsigned char aes_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// System state
volatile EncryptionMode_t currentMode = MODE_PLAINTEXT;
volatile EncryptionMode_t pendingMode = MODE_PLAINTEXT;
volatile uint32_t buttonPA6PressTime = 0;
volatile uint32_t buttonPA7PressTime = 0;
volatile uint32_t sequenceCounter = 0;

// ADC reading (shared between tasks)
volatile uint16_t adcValue = 0;
volatile float voltageReading = 0.0f;

// Debug counters to detect ISR entry
volatile uint32_t debugISRCounter = 0;
volatile uint32_t debugPA6Counter = 0;
volatile uint32_t debugPA7Counter = 0;

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_ADC1_Init(void);

void ADCReadTask(void const * argument);
void AESTask(void const * argument);
void ChaCha20Task(void const * argument);
void UARTTransmitTask(void const * argument);

/* USER CODE BEGIN PFP */
// Encryption Functions
static int add_pkcs7_padding(uint8_t *data, size_t data_len, size_t buffer_size);
static uint8_t calculate_checksum(const uint8_t *data, size_t length);
static void generate_random_iv(uint8_t *iv);
static int aes_encrypt_data(const uint8_t *plaintext, size_t plain_len,
                           uint8_t *ciphertext, size_t *cipher_len, uint8_t *iv);
static int chacha20_encrypt_data(const uint8_t *plaintext, size_t plain_len,
                                uint8_t *ciphertext, size_t *cipher_len);
int create_encrypted_frame(const uint8_t *encrypted, size_t enc_len,
                          uint8_t *frame, size_t *frame_len, EncryptionMode_t mode);

// Utility functions
int _write(int file, char *ptr, int len);
float read_voltage_mv(void);
void print_hex(const char* label, const uint8_t* data, size_t length);
const char* mode_to_string(EncryptionMode_t mode);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/**
 * @brief Printf redirect to UART (thread-safe with mutex)
 */
int _write(int file, char *ptr, int len)
{
    if (uartMutexHandle != NULL) {
        osMutexWait(uartMutexHandle, osWaitForever);
    }
    HAL_UART_Transmit(&huart2, (uint8_t *)ptr, len, HAL_MAX_DELAY);
    if (uartMutexHandle != NULL) {
        osMutexRelease(uartMutexHandle);
    }
    return len;
}

/**
 * @brief Convert mode enum to string
 */
const char* mode_to_string(EncryptionMode_t mode)
{
    switch(mode) {
        case MODE_PLAINTEXT: return "PLAINTEXT";
        case MODE_AES: return "AES-128";
        case MODE_CHACHA20: return "CHACHA20";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Print data in hex format
 */
void print_hex(const char* label, const uint8_t* data, size_t length)
{
    printf("%s [%u bytes]: ", label, (unsigned int)length);
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0 && i != length - 1) {
            printf("\r\n                    ");
        }
    }
    printf("\r\n");
}

/**
 * @brief Read voltage from ADC in millivolts
 */
float read_voltage_mv(void)
{
    uint32_t adc_raw = adcValue;
    return (adc_raw * VREF_MV) / (float)ADC_RESOLUTION;
}

/**
 * @brief Button interrupt callback - FIXED VERSION
 * Ensures proper toggle behavior for both buttons
 */
void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin)
{
    // Increment debug counter
    debugISRCounter++;

    if (GPIO_Pin == BUTTON_AES_PIN) {
        debugPA6Counter++;

        // If currently in AES mode, go back to plaintext
        if (currentMode == MODE_AES) {
            pendingMode = MODE_PLAINTEXT;
        }
        // Otherwise, switch to AES (from plaintext or chacha20)
        else {
            pendingMode = MODE_AES;
        }
    }
    else if (GPIO_Pin == BUTTON_CHACHA_PIN) {
        debugPA7Counter++;

        // If currently in ChaCha20 mode, go back to plaintext
        if (currentMode == MODE_CHACHA20) {
            pendingMode = MODE_PLAINTEXT;
        }
        // Otherwise, switch to ChaCha20 (from plaintext or AES)
        else {
            pendingMode = MODE_CHACHA20;
        }
    }
}

/**
 * @brief Add PKCS#7 padding
 */
static int add_pkcs7_padding(uint8_t *data, size_t data_len, size_t buffer_size)
{
    size_t padding_len = 16 - (data_len % 16);

    if (data_len + padding_len > buffer_size) {
        return -1;
    }

    for (size_t i = 0; i < padding_len; i++) {
        data[data_len + i] = (uint8_t)padding_len;
    }

    return data_len + padding_len;
}

/**
 * @brief Calculate XOR checksum
 */
static uint8_t calculate_checksum(const uint8_t *data, size_t length)
{
    uint8_t checksum = 0;
    for (size_t i = 0; i < length; i++) {
        checksum ^= data[i];
    }
    return checksum;
}

/**
 * @brief Generate IV
 */
static void generate_random_iv(uint8_t *iv)
{
    static uint32_t counter = 0;
    counter++;

    memcpy(iv, aes_iv, 16);
    iv[12] = (counter >> 24) & 0xFF;
    iv[13] = (counter >> 16) & 0xFF;
    iv[14] = (counter >> 8) & 0xFF;
    iv[15] = counter & 0xFF;
}

/**
 * @brief Encrypt data using AES-128 ECB
 */
static int aes_encrypt_data(const uint8_t *plaintext, size_t plain_len,
                           uint8_t *ciphertext, size_t *cipher_len,
                           uint8_t *iv)
{
    mbedtls_aes_context aes;
    uint8_t padded_buffer[MAX_ENCRYPTED_SIZE];
    int ret;
    int padded_len;

    (void)iv;  // IV not used in ECB mode

    if (plain_len > MAX_PLAINTEXT_SIZE) {
        return -1;
    }

    memcpy(padded_buffer, plaintext, plain_len);

    padded_len = add_pkcs7_padding(padded_buffer, plain_len, MAX_ENCRYPTED_SIZE);
    if (padded_len < 0) {
        return -2;
    }

    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_enc(&aes, aes_key, 128);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return ret;
    }

    // Encrypt block by block (ECB mode)
    for (int i = 0; i < padded_len; i += 16) {
        ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT,
                                     &padded_buffer[i], &ciphertext[i]);
        if (ret != 0) {
            mbedtls_aes_free(&aes);
            return ret;
        }
    }

    mbedtls_aes_free(&aes);

    *cipher_len = padded_len;
    return 0;
}

/**
 * @brief Encrypt data using ChaCha20
 */
static int chacha20_encrypt_data(const uint8_t *plaintext, size_t plain_len,
                                uint8_t *ciphertext, size_t *cipher_len)
{
    mbedtls_chacha20_context chacha;
    int ret;
    static uint32_t counter = 0;
    uint8_t nonce[12];

    if (plain_len > MAX_PLAINTEXT_SIZE) {
        return -1;
    }

    // Create unique nonce by incrementing counter
    memcpy(nonce, chacha20_nonce, 12);
    counter++;
    nonce[8] = (counter >> 24) & 0xFF;
    nonce[9] = (counter >> 16) & 0xFF;
    nonce[10] = (counter >> 8) & 0xFF;
    nonce[11] = counter & 0xFF;

    mbedtls_chacha20_init(&chacha);

    ret = mbedtls_chacha20_setkey(&chacha, chacha20_key);
    if (ret != 0) {
        mbedtls_chacha20_free(&chacha);
        return ret;
    }

    ret = mbedtls_chacha20_starts(&chacha, nonce, 0);
    if (ret != 0) {
        mbedtls_chacha20_free(&chacha);
        return ret;
    }

    ret = mbedtls_chacha20_update(&chacha, plain_len, plaintext, ciphertext);
    if (ret != 0) {
        mbedtls_chacha20_free(&chacha);
        return ret;
    }

    mbedtls_chacha20_free(&chacha);

    *cipher_len = plain_len;  // ChaCha20 doesn't require padding
    return 0;
}

/**
 * @brief Create encrypted frame with header and checksum
 */
int create_encrypted_frame(const uint8_t *encrypted, size_t enc_len,
                          uint8_t *frame, size_t *frame_len,
                          EncryptionMode_t mode)
{
    uint8_t iv_copy[16];
    size_t index = 0;

    frame[index++] = FRAME_START_BYTE;
    frame[index++] = (uint8_t)mode;  // Mode identifier
    frame[index++] = (enc_len >> 8) & 0xFF;
    frame[index++] = enc_len & 0xFF;

    generate_random_iv(iv_copy);
    memcpy(&frame[index], iv_copy, 16);
    index += 16;

    memcpy(&frame[index], encrypted, enc_len);
    index += enc_len;

    uint8_t checksum = calculate_checksum(&frame[1], index - 1);
    frame[index++] = checksum;
    frame[index++] = FRAME_END_BYTE;

    *frame_len = index;
    return 0;
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  HAL_Init();
  SystemClock_Config();
  MX_GPIO_Init();
  MX_USART2_UART_Init();
  MX_ADC1_Init();
  MX_MBEDTLS_Init();

  /* USER CODE BEGIN 2 */

  // Start ADC in continuous conversion mode
  if (HAL_ADC_Start(&hadc1) != HAL_OK) {
    Error_Handler();
  }

  HAL_Delay(1000);

  printf("\r\n\r\n");
  printf("========================================================\r\n");
  printf("  STM32 Multi-Mode Encrypted Voltage Monitor\r\n");
  printf("========================================================\r\n");
  printf("Build: %s %s\r\n", __DATE__, __TIME__);
  printf("Supported Modes:\r\n");
  printf("  - PLAINTEXT (default)\r\n");
  printf("  - AES-128 ECB\r\n");
  printf("  - ChaCha20\r\n");
  printf("ADC Resolution: 12-bit (0-4095)\r\n");
  printf("Voltage Range: 0.00V - 3.30V\r\n");
  printf("UART Baud Rate: 115200\r\n");
  printf("\r\n");
  printf("Controls:\r\n");
  printf("  - PA6: Toggle AES encryption ON/OFF\r\n");
  printf("  - PA7: Toggle ChaCha20 encryption ON/OFF\r\n");
  printf("  - Single press to switch modes\r\n");
  printf("\r\n");
  printf("Operation:\r\n");
  printf("  - Continuous ADC readings from potentiometer\r\n");
  printf("  - Press PA6 once to encrypt with AES\r\n");
  printf("  - Press PA6 again to return to plaintext\r\n");
  printf("  - Press PA7 once to encrypt with ChaCha20\r\n");
  printf("  - Press PA7 again to return to plaintext\r\n");
  printf("  - Can switch directly between encryption modes\r\n");
  printf("\r\n");
  printf("Current Mode: PLAINTEXT\r\n");
  printf("========================================================\r\n\r\n");

  /* USER CODE END 2 */

  /* Create mutexes */
  osMutexDef(uartMutex);
  uartMutexHandle = osMutexCreate(osMutex(uartMutex));

  /* Create queues */
  osMessageQDef(preEncryptQueue, PRE_ENCRYPT_QUEUE_SIZE, ADC_Reading_t);
  preEncryptQueueHandle = osMessageCreate(osMessageQ(preEncryptQueue), NULL);

  osMessageQDef(postEncryptQueue, POST_ENCRYPT_QUEUE_SIZE, EncryptedData_t*);
  postEncryptQueueHandle = osMessageCreate(osMessageQ(postEncryptQueue), NULL);

  /* Create threads */
  osThreadDef(ADCRead, ADCReadTask, osPriorityNormal, 0, 256);
  ADCReadTaskHandle = osThreadCreate(osThread(ADCRead), NULL);

  osThreadDef(AES, AESTask, osPriorityNormal, 0, 512);
  AESTaskHandle = osThreadCreate(osThread(AES), NULL);

  osThreadDef(ChaCha20, ChaCha20Task, osPriorityNormal, 0, 512);
  ChaCha20TaskHandle = osThreadCreate(osThread(ChaCha20), NULL);

  osThreadDef(UARTTransmit, UARTTransmitTask, osPriorityHigh, 0, 512);
  UARTTransmitTaskHandle = osThreadCreate(osThread(UARTTransmit), NULL);

  /* Start scheduler */
  osKernelStart();

  while (1)
  {
  }
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE3);

  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 16;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV4;
  RCC_OscInitStruct.PLL.PLLQ = 2;
  RCC_OscInitStruct.PLL.PLLR = 2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief ADC1 Initialization Function
  */
static void MX_ADC1_Init(void)
{
  ADC_ChannelConfTypeDef sConfig = {0};

  hadc1.Instance = ADC1;
  hadc1.Init.ClockPrescaler = ADC_CLOCK_SYNC_PCLK_DIV4;
  hadc1.Init.Resolution = ADC_RESOLUTION_12B;
  hadc1.Init.ScanConvMode = DISABLE;
  hadc1.Init.ContinuousConvMode = ENABLE;
  hadc1.Init.DiscontinuousConvMode = DISABLE;
  hadc1.Init.ExternalTrigConvEdge = ADC_EXTERNALTRIGCONVEDGE_NONE;
  hadc1.Init.ExternalTrigConv = ADC_SOFTWARE_START;
  hadc1.Init.DataAlign = ADC_DATAALIGN_RIGHT;
  hadc1.Init.NbrOfConversion = 1;
  hadc1.Init.DMAContinuousRequests = DISABLE;
  hadc1.Init.EOCSelection = ADC_EOC_SINGLE_CONV;
  if (HAL_ADC_Init(&hadc1) != HAL_OK)
  {
    Error_Handler();
  }

  sConfig.Channel = ADC_CHANNEL_0;
  sConfig.Rank = 1;
  sConfig.SamplingTime = ADC_SAMPLETIME_3CYCLES;
  if (HAL_ADC_ConfigChannel(&hadc1, &sConfig) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief USART2 Initialization Function
  */
static void MX_USART2_UART_Init(void)
{
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief GPIO Initialization Function
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : B1_Pin */
  GPIO_InitStruct.Pin = B1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : LD2_Pin */
  GPIO_InitStruct.Pin = LD2_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(LD2_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pins : PA6 PA7 (External Buttons with Interrupts) */
  GPIO_InitStruct.Pin = BUTTON_AES_PIN | BUTTON_CHACHA_PIN;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
  GPIO_InitStruct.Pull = GPIO_PULLUP;  // Enable pull-up for buttons
  HAL_GPIO_Init(BUTTON_GPIO_PORT, &GPIO_InitStruct);

  /* EXTI interrupt init for PA6 and PA7 */
  HAL_NVIC_SetPriority(EXTI9_5_IRQn, 6, 0);  // Priority 6 (lower priority than FreeRTOS max)
  HAL_NVIC_EnableIRQ(EXTI9_5_IRQn);
}

/* USER CODE BEGIN 4 */

/**
 * @brief ADC Read Task - Continuously reads ADC and queues data
 */
void ADCReadTask(void const * argument)
{
    ADC_Reading_t reading;
    uint32_t queueFailCount = 0;

    printf("[ADC_TASK] Started\r\n");
    osDelay(100);

    for(;;)
    {
        // Read ADC value
        adcValue = HAL_ADC_GetValue(&hadc1);
        voltageReading = read_voltage_mv();

        // Prepare reading structure
        reading.voltage = voltageReading;
        reading.adcValue = adcValue;
        reading.timestamp = HAL_GetTick();
        reading.sequenceNumber = sequenceCounter++;

        // Only queue if someone will process it
        // Check current and pending modes
        EncryptionMode_t activeMode = (pendingMode != currentMode) ? pendingMode : currentMode;

        // Only queue for encryption tasks if in encryption mode
        if (activeMode != MODE_PLAINTEXT) {
            if (osMessagePut(preEncryptQueueHandle, (uint32_t)&reading, 10) != osOK) {
                queueFailCount++;
                if (queueFailCount % 10 == 0) {
                    printf("[ADC_TASK] Warning: Pre-encrypt queue full! (fails: %lu)\r\n", queueFailCount);
                }
            }
        }
        // In plaintext mode, data is read directly by UART task via globals

        // Sample every 250ms (4 samples per second)
        osDelay(250);
    }
}

/**
 * @brief AES Task - Processes data when in AES mode
 */
void AESTask(void const * argument)
{
    osEvent evt;
    ADC_Reading_t reading;
    char plaintext[128];
    uint8_t encrypted[MAX_ENCRYPTED_SIZE];
    size_t enc_len;
    EncryptedData_t *encData;
    int ret;

    printf("[AES_TASK] Started\r\n");
    osDelay(150);

    for(;;)
    {
        // Check for mode change request FIRST
        if (pendingMode != MODE_AES && currentMode == MODE_AES) {
            currentMode = pendingMode;
            printf("\r\n>>> Switching to %s mode <<<\r\n\r\n",
                   mode_to_string(currentMode));
        }

        // Check if we should be active
        if (currentMode == MODE_AES || pendingMode == MODE_AES) {
            // Wait for data from pre-encrypt queue
            evt = osMessageGet(preEncryptQueueHandle, 100);

            if (evt.status == osEventMessage) {
                // Copy reading from queue
                memcpy(&reading, (void*)evt.value.p, sizeof(ADC_Reading_t));

                // Update mode if pending
                if (pendingMode == MODE_AES && currentMode != MODE_AES) {
                    currentMode = MODE_AES;
                    printf("\r\n>>> AES encryption activated <<<\r\n\r\n");
                }

                // Format plaintext
                int voltage_int = (int)(reading.voltage / 1000.0f);
                int voltage_frac = (int)((reading.voltage / 1000.0f - voltage_int) * 100);

                snprintf(plaintext, sizeof(plaintext),
                         "Voltage: %d.%02dV, ADC: %u, Seq: %lu",
                         voltage_int, voltage_frac, reading.adcValue, reading.sequenceNumber);

                printf("[AES_TASK] Plaintext: %s\r\n", plaintext);

                // Encrypt the data
                ret = aes_encrypt_data((uint8_t*)plaintext, strlen(plaintext),
                                      encrypted, &enc_len, NULL);

                if (ret == 0) {
                    // Allocate memory for encrypted data
                    encData = (EncryptedData_t*)pvPortMalloc(sizeof(EncryptedData_t));

                    if (encData != NULL) {
                        // Create frame with encrypted data
                        create_encrypted_frame(encrypted, enc_len,
                                             encData->data, &encData->length,
                                             MODE_AES);
                        encData->sequenceNumber = reading.sequenceNumber;
                        encData->mode = MODE_AES;

                        // Queue for transmission
                        if (osMessagePut(postEncryptQueueHandle, (uint32_t)encData, 100) != osOK) {
                            printf("[AES_TASK] Error: Post-encrypt queue full!\r\n");
                            vPortFree(encData);
                        }
                    } else {
                        printf("[AES_TASK] Error: Memory allocation failed!\r\n");
                    }
                } else {
                    printf("[AES_TASK] Error: Encryption failed: %d\r\n", ret);
                }
            }
        } else {
            // Not our turn, sleep longer
            osDelay(100);
        }
    }
}

/**
 * @brief ChaCha20 Task - Processes data when in ChaCha20 mode
 */
void ChaCha20Task(void const * argument)
{
    osEvent evt;
    ADC_Reading_t reading;
    char plaintext[128];
    uint8_t encrypted[MAX_ENCRYPTED_SIZE];
    size_t enc_len;
    EncryptedData_t *encData;
    int ret;

    printf("[CHACHA20_TASK] Started\r\n");
    osDelay(200);

    for(;;)
    {
        // Check for mode change request FIRST
        if (pendingMode != MODE_CHACHA20 && currentMode == MODE_CHACHA20) {
            currentMode = pendingMode;
            printf("\r\n>>> Switching to %s mode <<<\r\n\r\n",
                   mode_to_string(currentMode));
        }

        // Check if we should be active
        if (currentMode == MODE_CHACHA20 || pendingMode == MODE_CHACHA20) {
            // Wait for data from pre-encrypt queue
            evt = osMessageGet(preEncryptQueueHandle, 100);

            if (evt.status == osEventMessage) {
                // Copy reading from queue
                memcpy(&reading, (void*)evt.value.p, sizeof(ADC_Reading_t));

                // Update mode if pending
                if (pendingMode == MODE_CHACHA20 && currentMode != MODE_CHACHA20) {
                    currentMode = MODE_CHACHA20;
                    printf("\r\n>>> ChaCha20 encryption activated <<<\r\n\r\n");
                }

                // Format plaintext
                int voltage_int = (int)(reading.voltage / 1000.0f);
                int voltage_frac = (int)((reading.voltage / 1000.0f - voltage_int) * 100);

                snprintf(plaintext, sizeof(plaintext),
                         "Voltage: %d.%02dV, ADC: %u, Seq: %lu",
                         voltage_int, voltage_frac, reading.adcValue, reading.sequenceNumber);

                printf("[CHACHA20_TASK] Plaintext: %s\r\n", plaintext);

                // Encrypt the data
                ret = chacha20_encrypt_data((uint8_t*)plaintext, strlen(plaintext),
                                           encrypted, &enc_len);

                if (ret == 0) {
                    // Allocate memory for encrypted data
                    encData = (EncryptedData_t*)pvPortMalloc(sizeof(EncryptedData_t));

                    if (encData != NULL) {
                        // Create frame with encrypted data
                        create_encrypted_frame(encrypted, enc_len,
                                             encData->data, &encData->length,
                                             MODE_CHACHA20);
                        encData->sequenceNumber = reading.sequenceNumber;
                        encData->mode = MODE_CHACHA20;

                        // Queue for transmission
                        if (osMessagePut(postEncryptQueueHandle, (uint32_t)encData, 100) != osOK) {
                            printf("[CHACHA20_TASK] Error: Post-encrypt queue full!\r\n");
                            vPortFree(encData);
                        }
                    } else {
                        printf("[CHACHA20_TASK] Error: Memory allocation failed!\r\n");
                    }
                } else {
                    printf("[CHACHA20_TASK] Error: Encryption failed: %d\r\n", ret);
                }
            }
        } else {
            // Not our turn, sleep longer
            osDelay(100);
        }
    }
}

/**
 * @brief UART Transmit Task - Handles all UART output
 */
void UARTTransmitTask(void const * argument)
{
    osEvent evt;
    EncryptedData_t *encData;
    char plaintext[128];

    printf("[UART_TASK] Started\r\n");
    osDelay(250);

    for(;;)
    {
        // Check for mode transitions and report them
        static EncryptionMode_t lastReportedMode = MODE_PLAINTEXT;
        if (currentMode != lastReportedMode) {
            printf("\r\n>>> MODE CHANGED TO: %s <<<\r\n\r\n", mode_to_string(currentMode));
            lastReportedMode = currentMode;
        }

        if (currentMode == MODE_PLAINTEXT) {
            // In plaintext mode, read directly from volatile globals
            // Don't use queue to avoid blocking
            int voltage_int = (int)(voltageReading / 1000.0f);
            int voltage_frac = (int)((voltageReading / 1000.0f - voltage_int) * 100);

            snprintf(plaintext, sizeof(plaintext),
                     "Voltage: %d.%02dV, ADC: %u, Seq: %lu",
                     voltage_int, voltage_frac, adcValue, sequenceCounter);

            printf("[PLAINTEXT] %s\r\n", plaintext);

            osDelay(250); // Match ADC reading rate

        } else {
            // In encrypted mode, get from post-encrypt queue
            evt = osMessageGet(postEncryptQueueHandle, 500); // Longer timeout

            if (evt.status == osEventMessage) {
                encData = (EncryptedData_t*)evt.value.p;

                // Print mode and sequence
                printf("[%s] Seq: %lu - ", mode_to_string(encData->mode),
                       encData->sequenceNumber);

                // Print encrypted frame in hex
                print_hex("Encrypted Frame", encData->data, encData->length);

                // Free allocated memory
                vPortFree(encData);
            } else {
                // Timeout waiting for encrypted data
                printf("[UART_TASK] Timeout waiting for encrypted data in %s mode\r\n",
                       mode_to_string(currentMode));
            }
        }

        osDelay(10);
    }
}

/**
 * @brief Stack overflow hook callback
 */
void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName)
{
    (void)xTask;
    (void)pcTaskName;

    // Can't use printf here safely, just blink LED rapidly
    __disable_irq();
    while(1)
    {
        HAL_GPIO_TogglePin(LD2_GPIO_Port, LD2_Pin);
        for(volatile int i = 0; i < 100000; i++);
    }
}

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
    __disable_irq();
    printf("ERROR: System fault!\r\n");
    while (1)
    {
        HAL_GPIO_TogglePin(LD2_GPIO_Port, LD2_Pin);
        HAL_Delay(100);
    }
}

#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
    printf("Assert failed: %s:%lu\r\n", file, line);
}
#endif /* USE_FULL_ASSERT */

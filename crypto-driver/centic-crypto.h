#ifndef CENTIC_CRYPTO_H
#define CENTIC_CRYPTO_H


#include <linux/ioctl.h>   /* Defines macros for ioctl numbers */
#include <linux/types.h>

/* Register Offsets */
#define AXI_DMA_CONTROL_OFFSET      0x00 /* Control Reg */
#define AXI_DMA_STATUS_OFFSET       0x04 /* Status Reg */
#define AXI_DMA_CDESC_OFFSET		0x08 /* Current descriptor Reg */
#define AXI_DMA_TDESC_OFFSET		0x10 /* Tail descriptor Reg */

#define AXI_DMA_MM2S_OFFSET         0x00 /* Offet of Memory Map to Stream registers group*/
#define AXI_DMA_S2MM_OFFSET         0x30 /* Offet of Stream to Memory Map registers group*/


/* General register bits definitions */
/* Control Reg */
#define AXI_DMA_CR_RUNSTOP_MASK         0x00000001
#define AXI_DMA_CR_RESET_MASK           0x00000004 /* Reset DMA engine */

#define AXI_DMA_CR_EN_IRQ_IOC_MASK      0x00001000 /* Completion interrupt */
#define AXI_DMA_CR_EN_IRQ_DLY_MASK      0x00002000 /* Delay Timer interrupt */
#define AXI_DMA_CR_EN_IRQ_ERR_MASK      0x00004000 /* Error interrupt */
#define AXI_DMA_CR_EN_IRQ_ALL_MASK      0x00007000 /* All interrupts */

#define AXI_DMA_DELAY_MASK              0xFF000000 /* Delay timeout counter */
#define AXI_DMA_IRQ_THR_MASK            0x00FF0000 /* Interrupt Threshold counter */

/* Status Reg */
#define AXI_DMA_SR_HALTED_MASK          0x00000001 /* DMA channel halted */
#define AXI_DMA_SR_IDLE_MASK            0x00000002 /* DMA channel idle */

#define AXI_DMA_SR_SG_MASK              0x00000008 /* Scatter Gather mode*/
#define AXI_DMA_SR_DMA_INT_ERR_MASK     0x00000010 /* DMA Internal Error*/
#define AXI_DMA_SR_DMA_SLV_ERR_MASK     0x00000020 /* DMA Slave Error*/
#define AXI_DMA_SR_DMA_DEC_ERR_MASK     0x00000040 /* DMA Decode Error*/
#define AXI_DMA_SR_SG_INT_ERR_MASK      0x00000100 /* Scatter Gather Internal Error*/
#define AXI_DMA_SR_SG_SLV_ERR_MASK      0x00000200 /* Scatter Gather Slave Error*/
#define AXI_DMA_SR_SG_DEC_ERR_MASK      0x00000400 /* Scatter Gather Decode Error*/

#define AXI_DMA_SR_IOC_INT_MASK         0x00001000 /* Completion interrupt*/
#define AXI_DMA_SR_DLY_INT_MASK         0x00002000 /* Delay interrupt*/
#define AXI_DMA_SR_ERR_INT_MASK         0x00004000 /* Delay interrupt*/


#define AXI_DMA_SG_DESC_CR_LEN_MASK     0x007FFFFF
#define AXI_DMA_SG_DESC_CR_SOF_MASK     0x08000000
#define AXI_DMA_SG_DESC_CR_EOF_MASK     0x04000000

#define AXI_DMA_SG_DESC_NEXT_DESC_OFFSET       0x00
#define AXI_DMA_SG_DESC_BUF_ADDR_OFFSET        0x08
#define AXI_DMA_SG_DESC_CONTROL_OFFSET         0x18
#define AXI_DMA_SG_DESC_STATUS_OFFSET          0x1C
#define AXI_DMA_SG_DESC_MYADDR_OFFSET          0x34


//==================== CRYPTO REGISTERS
#define CT_CRYPTO_CORE_CONTROL_OFFSET               0x00
#define CT_CRYPTO_CORE_STATUS_OFFSET                0x04
#define CT_CRYPTO_CORE_ENCKEY_LENGTH_OFFSET         0x08
#define CT_CRYPTO_CORE_ENCKEY_OFFSET                0x0C
#define CT_CRYPTO_CORE_AUTHENKEY_LENGTH_OFFSET      0x2C
#define CT_CRYPTO_CORE_AUTHENKEY_OFFSET             0x30
#define CT_CRYPTO_CORE_ASSOC_LENGTH_OFFSET          0x70
#define CT_CRYPTO_CORE_IVSIZE_OFFSET                0x74
#define CT_CRYPTO_CORE_CRYPTO_LENGTH_OFFSET         0x78
#define CT_CRYPTO_CORE_AUTH_SIZE_OFFSET             0x7C
#define CT_CRYPTO_CORE_TX_COUNT_OFFSET              0x80
#define CT_CRYPTO_CORE_RX_COUNT_OFFSET              0x84
#define CT_CRYPTO_CORE_STATE_OFFSET                 0x88
#define CT_CRYPTO_HMAC_STATE_OFFSET                 0x8C
#define CT_CRYPTO_TIMER_COUNTER_OFFSET              0x90


#define CT_CRYPTO_CORE_CR_HASH_MD5_MODE                (0 << 8)
#define CT_CRYPTO_CORE_CR_HASH_SHA256_MODE             (1 << 8)

#define CT_CRYPTO_CORE_CR_AES_ECB_MODE                 (0 << 5)
#define CT_CRYPTO_CORE_CR_AES_CBC_MODE                 (1 << 5)

#define CT_CRYPTO_CORE_CR_ENCRYPT_DECRYPT_MASK         (1 << 4)
#define CT_CRYPTO_CORE_CR_RESET_MASK                   (1 << 3)


#define CTCRYP_IOCTL_MAGIC_NUMBER          0xFF

typedef struct {
    void *src;
    void *dest;
    int len;
    int retcode;
    unsigned long data_size;
    u64 time_spend;   //the time spend to transmited a data_size, data_size may be less than len;
}CTCRYP_Ioctl_Test_Dma_t;

#define CTCRYP_IOC_TEST_DMA             _IOWR(CTCRYP_IOCTL_MAGIC_NUMBER, 0, CTCRYP_Ioctl_Test_Dma_t *)

#define CTCRYP_IOC_RESET_STATISTICS     _IO(CTCRYP_IOCTL_MAGIC_NUMBER, 1)



#endif

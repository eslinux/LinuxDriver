#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/ioport.h>
#include <linux/of_irq.h>
#include <linux/interrupt.h>
#include <linux/crypto.h>
#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/authenc.h>
#include <crypto/des.h>
#include <crypto/md5.h>
#include <crypto/sha.h>
#include <crypto/internal/skcipher.h>

#include <linux/jiffies.h>
#include <linux/math64.h>

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/delay.h>

#include <linux/dma-mapping.h>
#include <linux/dmapool.h>

#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/rtnetlink.h>
#include <net/tcp.h>

#include "centic-crypto.h"

//#define DEBUG

#define SPEED_STATISTIC_ANALYSIS

//#define TEST_DMA

#define CENTIC_CRYPTO_ALG_PRIORITY	10000

#define CENTIC_CRYPTO_MAX_NUM_SG_DESC   128



#define CENTIC_CRYPTO_DMA_SG_DESC_CR_COMPLETED          0x80000000

#define CENTIC_CRYPTO_DMA_TEST_MAX_NUM_PAGES	128

#define CENTIC_CRYPTO_IPSEC_HASH_PG_SZ	64

#define CENTIC_CRYPTO_AEAD_FIFO_SIZE    512

# define _DPRINT(a...)

# define __DPRINT(a...)	do { printk("%s %u: ", __func__, __LINE__); printk (a); } while (0)

#ifdef DEBUG
# define DPRINT(a...)	do { printk("%s %u: ", __func__, __LINE__); printk (a); } while (0)
#else
# define DPRINT(a...)
#endif

#ifndef MIN
#define MIN(x,y) (((x) < (y)) ? x : y)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#ifndef list_last_entry
#define list_last_entry(ptr, type, member) \
        list_entry((ptr)->prev, type, member)
#endif
#endif

#define print_axi_sg_description_content(desc) \
        do { \
            printk("[0x%08X] bu_ad: 0x%08X - st: 0x%08X - nxt: 0x%08X - ctl: 0x%08X \n",desc->sg_desc_addr,\
            desc->hw.buf_addr,desc->hw.status,desc->hw.next_desc,desc->hw.control);\
        }\
        while(0)

struct centic_crypto_dma_request;
struct centic_crypto_engine;
struct centic_crypto_fops_context;


struct axi_dma_sg_desc{
    u32 next_desc;	/* 0x00 */
    u32 pad1;	/* 0x04 */
    u32 buf_addr;	/* 0x08 */
    u32 pad2;	/* 0x0C */
    u32 pad3;	/* 0x10 */
    u32 pad4;	/* 0x14 */
    u32 control;	/* 0x18 */
    volatile u32 status;	/* 0x1C */
    u32 app_0;	/* 0x20 */
    u32 app_1;	/* 0x24 */
    u32 app_2;	/* 0x28 */
    u32 app_3;	/* 0x2C */
    u32 app_4;	/* 0x30 */
};

#define AXI_DMA_SG_WRAPPER_BUSY         0x01

struct axi_dma_sg_desc_wrapper{
    struct axi_dma_sg_desc hw;
    struct list_head ring_entry;
    struct list_head req_entry;
    dma_addr_t sg_desc_dma_addr;
    volatile int flags;
}__aligned(64);


typedef void (*dma_request_complete_t)(struct centic_crypto_dma_request *);

#define CT_DMA_REQ_FLAGS_TO_DEVICE_DIRECTION    0x00000001
#define CT_DMA_REQ_FLAGS_SOF                    0x00000002

#define CT_DMA_REQ_FLAGS_STATE_MASK                   (7 << 2)
#define CT_DMA_REQ_FLAGS_STATE_PENDING                (0 << 2)
#define CT_DMA_REQ_FLAGS_STATE_PROCESSING             (1 << 2)
#define CT_DMA_REQ_FLAGS_STATE_COMPLETE               (2 << 2)

struct centic_crypto_dma_request {
    struct list_head entry;
    struct scatterlist *sg;
    int nents;
    int sgoff;
    volatile int flags;
    struct list_head sg_desc_list;
    struct centic_crypto_engine *engine;

    dma_request_complete_t complete;

    u32 app_registers[5];

    void *ctx;

    //struct axi_dma_sg_desc *last_sg_desc;
};

struct centic_crypto_aead_request {
    struct aead_request *req;
    struct list_head entry;
    struct centic_crypto_engine *engine;

    struct centic_crypto_dma_request tx_dma_assoc_request;
    struct centic_crypto_dma_request tx_dma_iv_request;
    struct centic_crypto_dma_request tx_dma_giv_request;
    struct centic_crypto_dma_request tx_dma_data_request;

    struct centic_crypto_dma_request rx_dma_giv_request;
    struct centic_crypto_dma_request rx_dma_data_request;

    int result;
    int is_encrypt;
    u8 *giv;
    size_t giv_len;
    struct scatterlist iv_sg;
    struct scatterlist giv_sg;
    unsigned long start_time;
    unsigned long end_time;
    size_t process_data_len;

};

struct centic_crypto_engine {
    struct cdev cdev;
    struct semaphore sem;
    void *crypto_res;
    void *dma_res;
    int tx_dma_irq;
    int rx_dma_irq;
    struct device *devp;
    struct list_head registered_algs;
    spinlock_t  dma_lock;
    spinlock_t  crypto_lock;
    struct dma_pool *sg_desc_pool;
    struct tasklet_struct axi_dma_interrupt_tasklet;
    struct tasklet_struct aead_request_flush_tasklet;
    struct proc_dir_entry *proc_dir;

    struct axi_dma_sg_desc_wrapper *tx_cur_sg_desc;
    struct axi_dma_sg_desc_wrapper *rx_cur_sg_desc;

    struct axi_dma_sg_desc_wrapper *tx_first_sg_desc;
    struct axi_dma_sg_desc_wrapper *rx_first_sg_desc;

    struct list_head tx_dma_req_pending;
    struct list_head tx_dma_req_processing;

    int tx_dma_partial_processing;

    int tx_dma_pending_count;
    int tx_max_dma_pending_count;

    int tx_dma_processing_count;
    int tx_max_dma_processing_count;

    int tx_dma_completed_count;
//    int tx_max_dma_completed_count;

    int tx_dma_err_count;


    struct list_head rx_dma_req_pending;
    struct list_head rx_dma_req_processing;
    int rx_dma_partial_processing;

    int rx_dma_pending_count;
    int rx_max_dma_pending_count;

    int rx_dma_processing_count;
    int rx_max_dma_processing_count;

    int rx_dma_completed_count;
//    int rx_max_dma_completed_count;

    int rx_dma_err_count;

    struct list_head crypto_aead_req_pending;
    struct list_head crypto_aead_req_processing;
    struct list_head crypto_aead_req_completed;
    struct list_head crypto_aead_req_pool;
    
    int crypto_aead_req_pending_count;
    int crypto_aead_req_max_pending_count;
    
    int crypto_aead_req_completed_count;
    int crypto_aead_req_failed_count;

    unsigned long pending_aead_size;

    unsigned long process_crypto_time;
    size_t process_crypto_len;

    unsigned int data_speed;
    unsigned int package_speed;

};


struct centic_crypto_alg {
    struct crypto_alg		alg;
    struct centic_crypto_engine *engine;
    struct list_head		entry;

};

struct centic_crypto_aead_tfm_ctx
{
    struct centic_crypto_engine		*engine;

    u8				cipher_key[AES_MAX_KEY_SIZE];
    u8				hash_ctx[CENTIC_CRYPTO_IPSEC_HASH_PG_SZ];
    u8				cipher_key_len;
    u8				hash_key_len;
    struct crypto_aead		*sw_cipher;
    size_t				auth_size;
    u8				salt[AES_BLOCK_SIZE];
    volatile int    exit;
    volatile int    busy;
};

struct centic_crypto_fops_context {
    struct semaphore sem;
    struct semaphore buff_sem;
    struct centic_crypto_engine *engine;
    struct centic_crypto_dma_request tx_dma_request;
    struct centic_crypto_dma_request rx_dma_request;
    int dma_ret;
    int ref_count;
    struct page *in_map[CENTIC_CRYPTO_DMA_TEST_MAX_NUM_PAGES];
    struct page *out_map[CENTIC_CRYPTO_DMA_TEST_MAX_NUM_PAGES];
    struct scatterlist in_sg[CENTIC_CRYPTO_DMA_TEST_MAX_NUM_PAGES];
    struct scatterlist out_sg[CENTIC_CRYPTO_DMA_TEST_MAX_NUM_PAGES];
    void *src;
    void *dest;
    int process_inplace;
    struct task_struct *process_task;
};

#define centic_crypto_defer_flush_dma_request(engine) \
    tasklet_schedule(&engine->axi_dma_interrupt_tasklet)

#define centic_crypto_defer_flush_aead_request(engine) \
    tasklet_schedule(&engine->aead_request_flush_tasklet)

static inline int sg_count(struct scatterlist *sg_list);
static int centic_crypto_flush_dma_request(struct centic_crypto_dma_request *req);
static int centic_crypto_flush_tx_dma_requests(struct centic_crypto_engine *engine);
static int centic_crypto_flush_rx_dma_requests(struct centic_crypto_engine *engine);
static int centic_crypto_submit_dma_request(struct centic_crypto_dma_request *req);

static int prepare_aead_dma_resources(struct centic_crypto_aead_request *aead_req,u8 *giv, bool is_encrypt);
static void free_aead_dma_resources(struct centic_crypto_aead_request *aead_req);
static void centic_crypto_aead_complete(struct centic_crypto_dma_request *dma_req);


static void file_ops_dma_complete(struct centic_crypto_dma_request * req) {
    struct centic_crypto_fops_context *file_ctx = (struct centic_crypto_fops_context *)req->ctx;
    DPRINT("Enter\n");
    if (!(req->flags & CT_DMA_REQ_FLAGS_TO_DEVICE_DIRECTION)) {
        up(&file_ctx->sem);
    }
    DPRINT("Enter\n");
}

static int centic_crypto_open(struct inode *inodep, struct file *filep) {
    struct centic_crypto_engine *engine;
    struct centic_crypto_fops_context *file_ctx;
    DPRINT("Enter\n");
    engine = container_of(inodep->i_cdev,struct centic_crypto_engine,cdev);

    if (down_interruptible(&engine->sem))
        return -1;

    file_ctx = (struct centic_crypto_fops_context *) devm_kzalloc(engine->devp,sizeof(struct centic_crypto_fops_context),GFP_KERNEL);
    if (file_ctx == NULL) {
        up(&engine->sem);
        return -ENOMEM;
    }
    file_ctx->engine = engine;

    sema_init(&file_ctx->sem,0);
    sema_init(&file_ctx->buff_sem,0);
    file_ctx->ref_count = 1;
    file_ctx->tx_dma_request.engine = engine;
    //file_ctx->tx_dma_request.flags|=CT_DMA_REQ_FLAGS_TO_DEVICE_DIRECTION|CT_DMA_REQ_FLAGS_SOF;
    file_ctx->tx_dma_request.flags|=CT_DMA_REQ_FLAGS_TO_DEVICE_DIRECTION;
    file_ctx->tx_dma_request.complete = file_ops_dma_complete;
    file_ctx->tx_dma_request.ctx = file_ctx;

    file_ctx->rx_dma_request.flags = 0;
    file_ctx->rx_dma_request.engine = engine;
    file_ctx->rx_dma_request.complete = file_ops_dma_complete;
    file_ctx->rx_dma_request.ctx = file_ctx;

    filep->private_data = file_ctx;

    up(&engine->sem);
    DPRINT("Exit\n");

    return 0;
}

static int centic_crypto_release(struct inode *inodep, struct file *filep) {
    struct centic_crypto_fops_context *file_ctx = (struct centic_crypto_fops_context *)filep->private_data;
    struct centic_crypto_engine *engine = file_ctx->engine;

    DPRINT("Enter\n");

    if (down_interruptible(&engine->sem))
        return -1;

    file_ctx->ref_count--;
    if (file_ctx->ref_count <= 0) {
        devm_kfree(engine->devp,(void *)file_ctx);
    }

    up(&engine->sem);

    DPRINT("Exit\n");
    return 0;
}

static long centic_crypto_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    int err = 0;
    struct centic_crypto_fops_context *file_ctx = (struct centic_crypto_fops_context *)filep->private_data;
    struct centic_crypto_engine *engine = file_ctx->engine;

    DPRINT("Enter ==========\n");

    switch (cmd) {
        case CTCRYP_IOC_RESET_STATISTICS:
            break;
        case CTCRYP_IOC_TEST_DMA:
            {
                CTCRYP_Ioctl_Test_Dma_t test_dma;
                int _ret1,_ret2,_ret,i;
                u64 start_time,finish_time;
                int rx_mapped_nents,tx_mapped_nents;
                int page_count, interrupt = 0;

                if ((err = copy_from_user(&test_dma,(CTCRYP_Ioctl_Test_Dma_t *)arg,sizeof(CTCRYP_Ioctl_Test_Dma_t)))) {
                    break;
                }

                if (( ((unsigned long)test_dma.src) & (PAGE_SIZE - 1))
                    ||(((unsigned long)test_dma.dest) & (PAGE_SIZE - 1)
                    ||(test_dma.len & (PAGE_SIZE - 1)))) {
                    DPRINT("Unsupport with none page aligned user buffers\n");
                    return -1;
                }

                file_ctx->src = test_dma.src;
                file_ctx->dest = test_dma.dest;
                page_count = test_dma.len >> PAGE_SHIFT;

                if (file_ctx->src == file_ctx->dest)
                    file_ctx->process_inplace = 1;
                else
                    file_ctx->process_inplace = 0;

                test_dma.time_spend = 0;
                test_dma.data_size = 0;
                while (page_count > 0 && !interrupt) {
                    if (file_ctx->process_inplace) {
                        if (page_count > CENTIC_CRYPTO_DMA_TEST_MAX_NUM_PAGES) {
                            _ret1 = get_user_pages_fast((unsigned long)file_ctx->dest,CENTIC_CRYPTO_DMA_TEST_MAX_NUM_PAGES,
                                                       1,file_ctx->out_map);
                        }
                        else {
                            _ret1 = get_user_pages_fast((unsigned long)file_ctx->dest,page_count,
                                                  1,file_ctx->out_map);
                        }
                        _ret = _ret1;

                        sg_init_table(file_ctx->out_sg,_ret);
                        for (i = 0; i < _ret; i++) {
                            SetPageDirty(file_ctx->out_map[i]);
                            page_cache_release(file_ctx->out_map[i]);
                            sg_set_page(&file_ctx->out_sg[i],file_ctx->out_map[i],PAGE_SIZE,0);
                        }

                        file_ctx->rx_dma_request.nents = dma_map_sg(file_ctx->engine->devp,file_ctx->out_sg,_ret,
                                DMA_BIDIRECTIONAL);
                        file_ctx->rx_dma_request.sg = file_ctx->out_sg;

                        file_ctx->tx_dma_request.nents = file_ctx->rx_dma_request.nents;
                        file_ctx->tx_dma_request.sg = file_ctx->out_sg;

                        _ret = rx_mapped_nents = tx_mapped_nents = file_ctx->rx_dma_request.nents;
                    }
                    else {
                        if (page_count > CENTIC_CRYPTO_DMA_TEST_MAX_NUM_PAGES) {
                            _ret1 = get_user_pages_fast((unsigned long)file_ctx->dest,CENTIC_CRYPTO_DMA_TEST_MAX_NUM_PAGES,
                                                       1,file_ctx->out_map);
                            _ret2 = get_user_pages_fast((unsigned long)file_ctx->src,CENTIC_CRYPTO_DMA_TEST_MAX_NUM_PAGES,
                                                0,file_ctx->in_map);
                        }
                        else {
                            _ret1 = get_user_pages_fast((unsigned long)file_ctx->dest,page_count,
                                                  1,file_ctx->out_map);
                            _ret2 = get_user_pages_fast((unsigned long)file_ctx->src,
                                                page_count,0,file_ctx->in_map);
                        }

                        _ret = MIN(_ret1,_ret2);

                        sg_init_table(file_ctx->out_sg,_ret);
                        for (i = 0; i < _ret; i++) {
                            SetPageDirty(file_ctx->out_map[i]);
                            page_cache_release(file_ctx->out_map[i]);
                            sg_set_page(&file_ctx->out_sg[i],file_ctx->out_map[i],PAGE_SIZE,0);
                        }
                        rx_mapped_nents = dma_map_sg(file_ctx->engine->devp,file_ctx->out_sg,_ret,
                                                     DMA_FROM_DEVICE);
                        file_ctx->rx_dma_request.sg = file_ctx->out_sg;

                        sg_init_table(file_ctx->in_sg,_ret);
                        for (i = 0; i < _ret; i++) {
                            SetPageDirty(file_ctx->in_map[i]);
                            page_cache_release(file_ctx->in_map[i]);
                            sg_set_page(&file_ctx->in_sg[i],file_ctx->in_map[i],PAGE_SIZE,0);
                        }

                        tx_mapped_nents = dma_map_sg(file_ctx->engine->devp,
                                                     file_ctx->in_sg,_ret,DMA_TO_DEVICE);

                        file_ctx->tx_dma_request.sg = file_ctx->in_sg;

                        _ret = MIN(rx_mapped_nents,tx_mapped_nents);
                        file_ctx->rx_dma_request.nents = _ret;
                        file_ctx->tx_dma_request.nents = _ret;
                    }

                    file_ctx->dest += (_ret << PAGE_SHIFT);
                    page_count -= _ret;
                    file_ctx->src += (_ret << PAGE_SHIFT);

                    start_time = jiffies_64;

                    centic_crypto_submit_dma_request(&file_ctx->rx_dma_request);
                    centic_crypto_submit_dma_request(&file_ctx->tx_dma_request);
                    centic_crypto_defer_flush_dma_request(engine);

                    if (down_interruptible(&file_ctx->sem)){
                        interrupt = 1;
                        down(&file_ctx->sem);//wait for last request is completed;
                    }

                    finish_time = jiffies_64;

                    if (time_after64(finish_time,start_time)) {
                        test_dma.time_spend += (finish_time - start_time);
                    }

                    test_dma.data_size += (_ret << PAGE_SHIFT);

                    if (file_ctx->process_inplace) {
                        dma_unmap_sg(file_ctx->engine->devp,file_ctx->rx_dma_request.sg,
                                     rx_mapped_nents,DMA_BIDIRECTIONAL);
                    }
                    else {
                        dma_unmap_sg(file_ctx->engine->devp,file_ctx->rx_dma_request.sg,
                                     rx_mapped_nents,DMA_FROM_DEVICE);

                        dma_unmap_sg(file_ctx->engine->devp,file_ctx->tx_dma_request.sg,
                                     tx_mapped_nents,DMA_TO_DEVICE);
                    }
                }

                test_dma.retcode = file_ctx->dma_ret;
                test_dma.time_spend = jiffies_to_usecs((unsigned long)test_dma.time_spend);

                if ((err = copy_to_user((CTCRYP_Ioctl_Test_Dma_t *)arg,&test_dma,sizeof(CTCRYP_Ioctl_Test_Dma_t)))) {
                    break;
                }
            }
            break;
        default :
            DPRINT("CTCRYP_ioctl: Error.Unknown ioctl\n");
            err = -ENOTTY;
            break;
    }

    DPRINT("Exit ================\n");
    return err;
}

#ifdef CONFIG_OF
static const struct of_device_id centic_crypto_of_id_table[] = {
    { .compatible = "xlnx,centic-crypto-1.00.a" },
    {}
};
#endif /* CONFIG_OF */

static const struct platform_device_id centic_crypto_id_table[] = {
    { "centic,centic-crypto", },
    { }
};

#ifdef SPEED_STATISTIC_ANALYSIS
int centic_crypto_proc_seq_show(struct seq_file *seq_filep, void *v)
{
    struct centic_crypto_engine *engine = (struct centic_crypto_engine *)seq_filep->private;

    if (down_interruptible(&engine->sem))
        return -1;

    seq_printf(seq_filep,"%-48s\t%d\n","Processed data speed (Mbps):",(engine->data_speed>>17));
    seq_printf(seq_filep,"%-48s\t%d\n","Processed package speed:",engine->package_speed);
    seq_printf(seq_filep,"%-48s\t%d\n","Max pending count:",engine->crypto_aead_req_max_pending_count);
    seq_printf(seq_filep,"%-48s\t%d\n","Current pending count:",engine->crypto_aead_req_pending_count);
    seq_printf(seq_filep,"%-48s\t%d\n","Completed package count:",engine->crypto_aead_req_completed_count);
    seq_printf(seq_filep,"%-48s\t%d\n","Failed package count:",engine->crypto_aead_req_failed_count);

    up(&engine->sem);
    return 0;
}

static int centic_crypto_proc_open(struct inode *nodep, struct file *filep)
{
    struct centic_crypto_engine *engine;

    DPRINT("Enter\n");
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
    engine = (struct centic_crypto_engine *)(PDE(nodep)->data);
#else
	engine = (struct centic_crypto_engine *)PDE_DATA(nodep);
#endif    
    

    if (down_interruptible(&engine->sem))
        return -1;

    if (single_open(filep,centic_crypto_proc_seq_show,engine)) {
        up(&engine->sem);
        return -ENOMEM;
    }

    up(&engine->sem);
    DPRINT("Exit\n");

    return 0;
}

static struct file_operations centic_crypto_proc_file_ops = {
      .owner = THIS_MODULE,
      .open = centic_crypto_proc_open,
      .llseek = seq_lseek,
      .read = seq_read,
      .release = seq_release,
};

static int centic_crypto_proc_init(struct centic_crypto_engine *engine) {
    engine->proc_dir = proc_create_data("centic-crypto-stat",0,NULL,&centic_crypto_proc_file_ops,engine);
    if (engine->proc_dir)
        return 0;

    return -ENOMEM;
}

static void centic_crypto_proc_release(struct centic_crypto_engine *engine) {
    if (engine->proc_dir) {
        #if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
            remove_proc_entry("centic-crypto-stat",NULL);
        #else
            proc_remove(engine->proc_dir);
        #endif
    }
}

#endif

static struct file_operations centic_crypto_file_ops = {
      .owner = THIS_MODULE,
      .unlocked_ioctl = centic_crypto_ioctl,
      .open = centic_crypto_open,
      .release = centic_crypto_release,
};



static int centic_crypto_aead_aes_setkey(struct crypto_aead *aead, const u8 *key,
                                         unsigned int len)
{
    struct crypto_tfm *tfm = crypto_aead_tfm(aead);
    struct centic_crypto_aead_tfm_ctx *ctx = crypto_tfm_ctx(tfm);
    int tmp;

    memcpy(ctx->cipher_key, key, len);
    tmp = len & (sizeof(u32) -1);
    if (tmp) {
        memset(ctx->cipher_key + len,0,(sizeof(u32) - tmp));
    }
    ctx->cipher_key_len = len;


    return 0;
}

static int centic_crypto_aead_setkey(struct crypto_aead *tfm, const u8 *key,unsigned int keylen)
{
    struct centic_crypto_aead_tfm_ctx *ctx = crypto_aead_ctx(tfm);
    int tmp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
    struct crypto_authenc_key_param *param;
    unsigned int authkeylen, enckeylen;
    int err = -EINVAL;
    struct rtattr *rta = (void *)key;

    DPRINT("Enter\n");

    if (!RTA_OK(rta, keylen))
        goto badkey;

    if (rta->rta_type != CRYPTO_AUTHENC_KEYA_PARAM)
        goto badkey;

    if (RTA_PAYLOAD(rta) < sizeof(*param))
        goto badkey;

    param = RTA_DATA(rta);
    enckeylen = be32_to_cpu(param->enckeylen);

    key += RTA_ALIGN(rta->rta_len);
    keylen -= RTA_ALIGN(rta->rta_len);

    if (keylen < enckeylen)
        goto badkey;

    authkeylen = keylen - enckeylen;

    if (enckeylen > AES_MAX_KEY_SIZE)
        goto badkey;

    if (authkeylen > sizeof(ctx->hash_ctx))
        goto badkey;

    err = centic_crypto_aead_aes_setkey(tfm, key + authkeylen, enckeylen);

    if (err)
        goto badkey;

    memcpy(ctx->hash_ctx, key, authkeylen);
    tmp = authkeylen & (sizeof(u32) -1);
    if (tmp) {
        memset(ctx->hash_ctx + authkeylen,0,(sizeof(u32) - tmp));
    }
    ctx->hash_key_len = authkeylen;
#else
    struct crypto_authenc_keys keys;
    int err = -EINVAL;

    DPRINT("Enter\n");

    if (crypto_authenc_extractkeys(&keys, key, keylen) != 0)
        goto badkey;

    if (keys.enckeylen > AES_MAX_KEY_SIZE)
        goto badkey;

    if (keys.authkeylen > sizeof(ctx->hash_ctx))
        goto badkey;

    err = centic_crypto_aead_aes_setkey(tfm, keys.enckey, keys.enckeylen);

    if (err)
        goto badkey;

    memcpy(ctx->hash_ctx, keys.authkey, keys.authkeylen);
    tmp = keys.authkeylen & (sizeof(u32) -1);
    if (tmp) {
        memset(ctx->hash_ctx + keys.authkeylen,0,(sizeof(u32) - tmp));
    }
    ctx->hash_key_len = keys.authkeylen;
#endif
    return 0;

badkey:
    crypto_aead_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
    return -EINVAL;
}

static int centic_crypto_aead_setauthsize(struct crypto_aead *tfm,
                  unsigned int authsize) {
    struct centic_crypto_aead_tfm_ctx *ctx = crypto_aead_ctx(tfm);

    ctx->auth_size = authsize;
    return 0;
}

static int prepare_aead_dma_resources(struct centic_crypto_aead_request *aead_req,u8 *giv, bool is_encrypt)
{
    struct crypto_aead *aead = crypto_aead_reqtfm(aead_req->req);
    struct centic_crypto_aead_tfm_ctx *ctx = crypto_aead_ctx(aead);
    struct centic_crypto_engine *engine = ctx->engine;

    size_t ivsize;
    u8 *iv;

    if (aead_req->giv) {
        iv = aead_req->giv;
        ivsize = aead_req->giv_len;
    }
    else {
        iv = aead_req->req->iv;
        ivsize = crypto_aead_ivsize(crypto_aead_reqtfm(aead_req->req));
    }

    aead_req->tx_dma_assoc_request.nents = 0;
    aead_req->tx_dma_iv_request.nents = 0;
    aead_req->tx_dma_giv_request.nents = 0;
    aead_req->rx_dma_giv_request.nents = 0;
    aead_req->tx_dma_data_request.nents = 0;
    aead_req->rx_dma_data_request.nents = 0;


    //request tx dma for associated data
    if (aead_req->req->assoclen > 0) {
        aead_req->tx_dma_assoc_request.engine = engine;
        aead_req->tx_dma_assoc_request.complete = 0;
        aead_req->tx_dma_assoc_request.ctx = (void *)aead_req;
        aead_req->tx_dma_assoc_request.sg = aead_req->req->assoc;
        aead_req->tx_dma_assoc_request.nents = dma_map_sg(engine->devp,
                                                         aead_req->req->assoc,
                                                         sg_nents(aead_req->req->assoc),DMA_TO_DEVICE);
        if (aead_req->tx_dma_assoc_request.nents <= 0)
            goto fail_prepare_aead_dma_resources;

        aead_req->tx_dma_assoc_request.flags = CT_DMA_REQ_FLAGS_TO_DEVICE_DIRECTION;
    }

    //request tx dma for iv data
    sg_init_one(&aead_req->iv_sg,(void *)iv,ivsize);

    aead_req->tx_dma_iv_request.engine = engine;
    aead_req->tx_dma_iv_request.complete = 0;
    aead_req->tx_dma_iv_request.ctx = (void *)aead_req;
    aead_req->tx_dma_iv_request.sg = &aead_req->iv_sg;
    aead_req->tx_dma_iv_request.nents = dma_map_sg(engine->devp,
                                                     &aead_req->iv_sg,
                                                     1,DMA_TO_DEVICE);
    if (aead_req->tx_dma_iv_request.nents <= 0)
        goto fail_prepare_aead_dma_resources;

    aead_req->tx_dma_iv_request.flags = CT_DMA_REQ_FLAGS_TO_DEVICE_DIRECTION;

    //request tx & rx dma for crypto data
    if (aead_req->req->src == aead_req->req->dst) {
        aead_req->tx_dma_data_request.engine = engine;
        aead_req->tx_dma_data_request.complete = 0;
        aead_req->tx_dma_data_request.ctx = (void *)aead_req;
        aead_req->tx_dma_data_request.sg = aead_req->req->src;
        aead_req->tx_dma_data_request.nents = dma_map_sg(engine->devp,
                                                         aead_req->req->src,
                                                         sg_nents(aead_req->req->src),DMA_BIDIRECTIONAL);

        if (aead_req->tx_dma_data_request.nents <= 0)
            goto fail_prepare_aead_dma_resources;

        aead_req->tx_dma_data_request.flags = CT_DMA_REQ_FLAGS_TO_DEVICE_DIRECTION;

        aead_req->rx_dma_data_request.engine = engine;
        aead_req->rx_dma_data_request.complete = centic_crypto_aead_complete;
        aead_req->rx_dma_data_request.ctx = (void *)aead_req;
        aead_req->rx_dma_data_request.sg = aead_req->req->src;
        aead_req->rx_dma_data_request.nents = aead_req->tx_dma_data_request.nents;
        aead_req->rx_dma_data_request.flags = 0;
    }
    else{
        int nents = sg_nents(aead_req->req->src);

        aead_req->tx_dma_data_request.engine = engine;
        aead_req->tx_dma_data_request.complete = 0;
        aead_req->tx_dma_data_request.ctx = (void *)aead_req;
        aead_req->tx_dma_data_request.sg = aead_req->req->src;
        aead_req->tx_dma_data_request.nents = dma_map_sg(engine->devp,
                                                         aead_req->req->src,
                                                         nents,DMA_TO_DEVICE);

        if (aead_req->tx_dma_data_request.nents <= 0)
            goto fail_prepare_aead_dma_resources;

        aead_req->tx_dma_data_request.flags = CT_DMA_REQ_FLAGS_TO_DEVICE_DIRECTION;

        aead_req->rx_dma_data_request.engine = engine;
        aead_req->rx_dma_data_request.complete = centic_crypto_aead_complete;
        aead_req->rx_dma_data_request.ctx = (void *)aead_req;
        aead_req->rx_dma_data_request.sg = aead_req->req->dst;
        aead_req->rx_dma_data_request.nents = dma_map_sg(engine->devp,
                                                        aead_req->req->dst,
                                                        nents,DMA_FROM_DEVICE);

        if (aead_req->rx_dma_data_request.nents <= 0)
            goto fail_prepare_aead_dma_resources;

        aead_req->rx_dma_data_request.flags = 0;
    }

    return 0;
fail_prepare_aead_dma_resources:
    DPRINT("== fail_prepare_aead_dma_resources ===\n");
    if (aead_req->tx_dma_assoc_request.nents > 0) {
        dma_unmap_sg(engine->devp,aead_req->tx_dma_assoc_request.sg,aead_req->tx_dma_assoc_request.nents,DMA_TO_DEVICE);
    }
    if (aead_req->tx_dma_iv_request.nents > 0) {
        dma_unmap_sg(engine->devp,aead_req->tx_dma_iv_request.sg,aead_req->tx_dma_iv_request.nents,DMA_TO_DEVICE);
    }
#if 0
    if (aead_req->tx_dma_giv_request.nents > 0) {
        dma_unmap_sg(engine->devp,aead_req->tx_dma_giv_request.sg,aead_req->tx_dma_giv_request.nents,DMA_BIDIRECTIONAL);
    }
#endif
    if (aead_req->req->src == aead_req->req->dst) {
        if (aead_req->tx_dma_data_request.nents > 0) {
            dma_unmap_sg(engine->devp,aead_req->tx_dma_data_request.sg,aead_req->tx_dma_data_request.nents,DMA_BIDIRECTIONAL);
        }
    }
    else {
        if (aead_req->tx_dma_data_request.nents > 0) {
            dma_unmap_sg(engine->devp,aead_req->tx_dma_data_request.sg,aead_req->tx_dma_data_request.nents,DMA_TO_DEVICE);
        }
        if (aead_req->rx_dma_data_request.nents > 0) {
            dma_unmap_sg(engine->devp,aead_req->rx_dma_data_request.sg,aead_req->rx_dma_data_request.nents,DMA_FROM_DEVICE);
        }
    }
    return -ENOMEM;
}

static void free_aead_dma_resources(struct centic_crypto_aead_request *aead_req) {
    struct crypto_aead *aead = crypto_aead_reqtfm(aead_req->req);
    struct centic_crypto_aead_tfm_ctx *ctx = crypto_aead_ctx(aead);
    struct centic_crypto_engine *engine = ctx->engine;

    if (aead_req->tx_dma_assoc_request.nents > 0) {
        dma_unmap_sg(engine->devp,aead_req->tx_dma_assoc_request.sg,aead_req->tx_dma_assoc_request.nents,DMA_TO_DEVICE);
    }
    if (aead_req->tx_dma_iv_request.nents > 0) {
        dma_unmap_sg(engine->devp,aead_req->tx_dma_iv_request.sg,aead_req->tx_dma_iv_request.nents,DMA_TO_DEVICE);
    }
#if 0
    if (aead_req->tx_dma_giv_request.nents > 0) {
        dma_unmap_sg(engine->devp,aead_req->tx_dma_giv_request.sg,aead_req->tx_dma_giv_request.nents,DMA_BIDIRECTIONAL);
    }
#endif
    if (aead_req->req->src == aead_req->req->dst) {
        if (aead_req->tx_dma_data_request.nents > 0) {
            dma_unmap_sg(engine->devp,aead_req->tx_dma_data_request.sg,aead_req->tx_dma_data_request.nents,DMA_BIDIRECTIONAL);
        }
    }
    else {
        if (aead_req->tx_dma_data_request.nents > 0) {
            dma_unmap_sg(engine->devp,aead_req->tx_dma_data_request.sg,aead_req->tx_dma_data_request.nents,DMA_TO_DEVICE);
        }
        if (aead_req->rx_dma_data_request.nents > 0) {
            dma_unmap_sg(engine->devp,aead_req->rx_dma_data_request.sg,aead_req->rx_dma_data_request.nents,DMA_FROM_DEVICE);
        }
    }
}

static inline int centic_crypto_aead_submit(struct aead_request *req,u8 *giv, bool is_encrypt)
{
    struct crypto_aead *aead = crypto_aead_reqtfm(req);
    struct centic_crypto_aead_tfm_ctx *ctx = crypto_aead_ctx(aead);
    struct centic_crypto_engine *engine = ctx->engine;
    struct centic_crypto_aead_request *aead_req;
    int err = -EINPROGRESS;

    DPRINT("Enter\n");

    if (ctx->exit)
        return -EBUSY;

    if (list_empty(&engine->crypto_aead_req_pool)) {
        return -EBUSY;
    }

    if (req->cryptlen >= (1<<16) ||
        req->assoclen >= (1<<16)){
        return -EFAULT;
    }

    aead_req = list_first_entry(&engine->crypto_aead_req_pool,struct centic_crypto_aead_request,entry);

    if (is_encrypt) {
        aead_req->process_data_len = ((req->cryptlen + ctx->auth_size) << 1)
                + req->assoclen + crypto_aead_ivsize(aead);
    }
    else {
        aead_req->process_data_len = (req->cryptlen << 1) + req->assoclen + crypto_aead_ivsize(aead);
    }

    aead_req->engine = engine;
    aead_req->req = req;
    aead_req->is_encrypt = is_encrypt;
    aead_req->giv = giv;
    aead_req->giv_len = giv ? crypto_aead_ivsize(aead) : 0;
    aead_req->result = -EBUSY;

    if (prepare_aead_dma_resources(aead_req,giv,is_encrypt)) {
        return -EFAULT;
    }


    engine->pending_aead_size += aead_req->process_data_len;

    list_move_tail(&aead_req->entry,&engine->crypto_aead_req_pending);
    engine->crypto_aead_req_pending_count++;
    if (engine->crypto_aead_req_pending_count > engine->crypto_aead_req_max_pending_count) {
        engine->crypto_aead_req_max_pending_count = engine->crypto_aead_req_pending_count;
    }

    if (list_empty(&engine->crypto_aead_req_processing)){
        centic_crypto_defer_flush_aead_request(engine);
    }

    DPRINT("Exit\n");
    return err;
}

static int centic_crypto_aead_encrypt(struct aead_request *req)
{
    struct crypto_aead *tfm = crypto_aead_reqtfm(req);
    struct  centic_crypto_aead_tfm_ctx *tfm_ctx = crypto_aead_ctx(tfm);
    struct centic_crypto_engine *engine = tfm_ctx->engine;
    int err = -EBUSY;
    unsigned long flags;

    DPRINT("Enter\n");
    spin_lock_irqsave(&engine->crypto_lock, flags);
    err = centic_crypto_aead_submit(req,NULL,1);
    spin_unlock_irqrestore(&engine->crypto_lock, flags);
    DPRINT("Exit\n");
    return err;
}

static int centic_crypto_aead_decrypt(struct aead_request *req)
{
    struct crypto_aead *tfm = crypto_aead_reqtfm(req);
    struct centic_crypto_aead_tfm_ctx *tfm_ctx = crypto_aead_ctx(tfm);
    struct centic_crypto_engine *engine = tfm_ctx->engine;
    int err = -EBUSY;
    unsigned long flags;

    DPRINT("Enter\n");
    spin_lock_irqsave(&engine->crypto_lock, flags);

    err = centic_crypto_aead_submit(req,NULL,0);

    spin_unlock_irqrestore(&engine->crypto_lock, flags);
    DPRINT("Exit\n");

    return err;
}

static int centic_crypto_aead_givencrypt(struct aead_givcrypt_request *req)
{
    struct crypto_aead *tfm = aead_givcrypt_reqtfm(req);
    struct  centic_crypto_aead_tfm_ctx *tfm_ctx = crypto_aead_ctx(tfm);
    struct centic_crypto_engine *engine = tfm_ctx->engine;
    size_t ivsize = crypto_aead_ivsize(tfm);
    unsigned len;
    __be64 seq;
    int err = -EBUSY;
    unsigned long flags;

    DPRINT("Enter\n");

    spin_lock_irqsave(&engine->crypto_lock, flags);

#if 0
    memcpy(req->areq.iv, tfm_ctx->salt, ivsize);
    len = ivsize;
    if (ivsize > sizeof(u64)) {
        memset(req->giv, 0, ivsize - sizeof(u64));
        len = sizeof(u64);
    }
    seq = cpu_to_be64(req->seq);
    memcpy(req->giv + ivsize - len, &seq, len);
#else
    memcpy(req->giv, tfm_ctx->salt, ivsize);
    len = ivsize;
    if (ivsize > sizeof(u64)) {
        //memset(req->giv, 0, ivsize - sizeof(u64));
        len = sizeof(u64);
    }
    seq = cpu_to_be64(req->seq);
    memcpy(req->giv + ivsize - len, &seq, len);
#endif

    err = centic_crypto_aead_submit(&req->areq,req->giv,1);

    spin_unlock_irqrestore(&engine->crypto_lock, flags);
    DPRINT("Exit\n");
    return err;
}

static int centic_crypto_aead_cra_init(struct crypto_tfm *tfm)
{
    struct centic_crypto_aead_tfm_ctx *ctx = crypto_tfm_ctx(tfm);
    struct crypto_alg *alg = tfm->__crt_alg;
    struct centic_crypto_alg *our_alg = container_of(alg,struct centic_crypto_alg,alg);
    struct centic_crypto_engine *engine = our_alg->engine;


    DPRINT("Enter\n");

    ctx->engine = engine;
    ctx->exit = 0;
    ctx->busy = 0;

    get_random_bytes(ctx->salt, sizeof(ctx->salt));

    DPRINT("Exit\n");

    return 0;
}

static void centic_crypto_aead_cra_exit(struct crypto_tfm *tfm)
{
    struct centic_crypto_aead_tfm_ctx *ctx = crypto_tfm_ctx(tfm);
    struct centic_crypto_engine *engine = ctx->engine;
    struct centic_crypto_aead_request *aead_req,*next;
    struct list_head abort_list;
    unsigned long flags;
    DPRINT("Enter\n");

    spin_lock_irqsave(&engine->crypto_lock, flags);

    ctx->exit = 1;

    INIT_LIST_HEAD(&abort_list);

    list_for_each_entry_safe(aead_req,next,&engine->crypto_aead_req_pending,entry){
        if (&(crypto_aead_reqtfm(aead_req->req)->base) == tfm) {
            engine->crypto_aead_req_pending_count--;
            list_move_tail(&aead_req->entry,&abort_list);
        }
    }
    spin_unlock_irqrestore(&engine->crypto_lock, flags);

    list_for_each_entry_safe(aead_req,next,&abort_list,entry){
        free_aead_dma_resources(aead_req);
        engine->crypto_aead_req_completed_count++;
        engine->crypto_aead_req_failed_count++;
        aead_req->result = -EFAULT;
        spin_lock_irqsave(&engine->crypto_lock, flags);
        list_move_tail(&aead_req->entry,&engine->crypto_aead_req_pool);
        spin_unlock_irqrestore(&engine->crypto_lock, flags);
        aead_req->req->base.complete(&aead_req->req->base,aead_req->result);
    }

    while(ctx->busy);

    DPRINT("Exit Pending: %d - Processing: %d \n",
           engine->crypto_aead_req_pending_count,!list_empty(&engine->crypto_aead_req_processing));
}


static void     centic_crypto_aead_complete(struct centic_crypto_dma_request *dma_req)
{
    struct centic_crypto_engine *engine = dma_req->engine;
    struct centic_crypto_aead_request *aead_req =
            (struct centic_crypto_aead_request *)dma_req->ctx,*next;

    struct crypto_aead *tfm = crypto_aead_reqtfm(aead_req->req);
    struct  centic_crypto_aead_tfm_ctx *tfm_ctx = crypto_aead_ctx(tfm);
    struct list_head completed_list;
    unsigned long flags;

    DPRINT("Enter\n");

    spin_lock_irqsave(&engine->crypto_lock, flags);

    INIT_LIST_HEAD(&completed_list);

    list_move_tail(&aead_req->entry,&completed_list);

    spin_unlock_irqrestore(&engine->crypto_lock, flags);

    list_for_each_entry_safe(aead_req,next,&completed_list,entry){
        free_aead_dma_resources(aead_req);

        engine->crypto_aead_req_completed_count++;
        engine->pending_aead_size -= aead_req->process_data_len;
#ifdef _DEBUG
    {
        void *_data = sg_virt(aead_req->rx_dma_data_request.sg);
        int i;
        int len = (aead_req->req->cryptlen +
                   ((struct centic_crypto_aead_tfm_ctx *)crypto_aead_ctx(crypto_aead_reqtfm(aead_req->req)))->auth_size);
        printk("Result Data: ");
        for (i = 0;i<len; i++) {
            if ((i % 8) == 0)
                printk("\n");
            printk("%02X ",((char *)_data)[i]);
        }
        printk("\n");
    }
#endif

        /*aead_req->result = readl(engine->crypto_res + CT_CRYPTO_CORE_STATUS_OFFSET);
        if (readl(engine->crypto_res + CT_CRYPTO_CORE_STATUS_OFFSET) == 0) {
            engine->crypto_aead_req_failed_count++;
            aead_req->result =
        }*/
        aead_req->end_time = readl(engine->crypto_res + CT_CRYPTO_TIMER_COUNTER_OFFSET);
        
        if (aead_req->end_time > aead_req->start_time) {
            engine->process_crypto_time += (aead_req->end_time - aead_req->start_time);
            engine->process_crypto_len += aead_req->process_data_len;
		}
		
		if ((engine->crypto_aead_req_completed_count % 500) == 0) {
            if (engine->process_crypto_time > 0){
                engine->data_speed = div64_u64((u64)engine->process_crypto_len*1000*1000*100,
                                (u64)engine->process_crypto_time);
                engine->package_speed = div_u64((u64)500000000 * 100,engine->process_crypto_time);
            }

            engine->process_crypto_time = 0;
			engine->process_crypto_len = 0;	
		}		

        aead_req->result = 0;

        spin_lock_irqsave(&engine->crypto_lock, flags);
        list_move_tail(&aead_req->entry,&engine->crypto_aead_req_pool);
        spin_unlock_irqrestore(&engine->crypto_lock, flags);

        tfm_ctx->busy = 0;

        aead_req->req->base.complete(&aead_req->req->base,aead_req->result);
        _DPRINT("Exit");
    }

    spin_lock_irqsave(&engine->crypto_lock, flags);
    if (list_empty(&engine->crypto_aead_req_processing)
            && !list_empty(&engine->crypto_aead_req_pending)) {
        centic_crypto_defer_flush_aead_request(engine);
    }
    spin_unlock_irqrestore(&engine->crypto_lock, flags);

    DPRINT("Exit\n");
}

/* Count the number of scatterlist entries in a scatterlist. */
static inline int sg_count(struct scatterlist *sg_list)
{
    struct scatterlist *sg = sg_list;
    int sg_nents = 0;
    int size = 0;

    while (sg != NULL) {
        ++sg_nents;
        size+=sg_dma_len(sg);
        sg = sg_next(sg);
    }

    _DPRINT("Size of SG List: %d - SG nent: %d\n",size,sg_nents);

    return sg_nents;
}

static void aead_request_flush_tasklet_handler(unsigned long data) {
    struct crypto_aead *aead;
    struct centic_crypto_aead_tfm_ctx *ctx;
    struct centic_crypto_engine *engine = (struct centic_crypto_engine *)data;
    struct centic_crypto_aead_request *aead_req;
    u32 *u32_val;
    int i,len,crypt_len;
    int offs;
    size_t ivsize;
    void *iv;
    unsigned long flags;

    DPRINT("Enter\n");

    spin_lock_irqsave(&engine->crypto_lock, flags);

    if (list_empty(&engine->crypto_aead_req_pending)) {
        spin_unlock_irqrestore(&engine->crypto_lock, flags);
        return;
    }


    aead_req = list_first_entry(&engine->crypto_aead_req_pending,struct centic_crypto_aead_request,entry);
    engine->crypto_aead_req_pending_count--;

    list_move_tail(&aead_req->entry,&engine->crypto_aead_req_processing);

    aead = crypto_aead_reqtfm(aead_req->req);
    ctx = crypto_aead_ctx(aead);

    ctx->busy = 1;

    spin_unlock_irqrestore(&engine->crypto_lock, flags);

    aead_req->start_time = readl(engine->crypto_res + CT_CRYPTO_TIMER_COUNTER_OFFSET);

    if (aead_req->giv) {
        iv = aead_req->giv;
        ivsize = aead_req->giv_len;
    }
    else {
        iv = aead_req->req->iv;
        ivsize = crypto_aead_ivsize(crypto_aead_reqtfm(aead_req->req));
    }

    _DPRINT("ivsize: %d - cryptlen: %d - assoclen: %d - keylen: %d - hashlen: %d - authenlen: %d - giv_len: %d\n",
           ivsize,aead_req->req->cryptlen,aead_req->req->assoclen,ctx->cipher_key_len,
           ctx->hash_key_len, ctx->auth_size, aead_req->giv_len);

    aead_req->result = -EINPROGRESS;

#ifdef _DEBUG
    {
        void *_key = ctx->cipher_key;
        printk("Key: ");
        for (i = 0;i < ctx->cipher_key_len; i++) {
            printk("%02X ",((char *)_key)[i]);
        }
        printk("\n");
    }
#endif

#ifdef _DEBUG
    {
        void *_data = sg_virt(aead_req->req->assoc);
        printk("Associated Data: ");
        for (i = 0;i<(aead_req->req->assoclen); i++) {
            if ((i % 8) == 0)
                printk("\n");
            printk("%02X ",((char *)_data)[i]);
        }
        printk("\n");
    }
#endif

#ifdef _DEBUG
    {
        void *_data = iv;
        printk("IV: ");
        for (i = 0;i<ivsize; i++) {
            printk("%02X ",((char *)_data)[i]);
        }
        printk("\n");
    }
#endif

#ifdef _DEBUG
    {
        void *_data = sg_virt(aead_req->req->src);
        printk("Data: ");
        for (i = 0;i<(aead_req->req->cryptlen + ctx->auth_size); i++) {
            if ((i % 8) == 0)
                printk("\n");
            printk("%02X ",((char *)_data)[i]);
        }
        printk("\n");
    }
#endif
    //set register and flush dma request at here
    //writel(CT_CRYPTO_CORE_CR_RESET_MASK,engine->crypto_res + CT_CRYPTO_CORE_CONTROL_OFFSET);

    //set control register
    writel(aead_req->is_encrypt ? (CT_CRYPTO_CORE_CR_HASH_SHA256_MODE|CT_CRYPTO_CORE_CR_AES_CBC_MODE|CT_CRYPTO_CORE_CR_ENCRYPT_DECRYPT_MASK) :
             (CT_CRYPTO_CORE_CR_HASH_SHA256_MODE|CT_CRYPTO_CORE_CR_AES_CBC_MODE), engine->crypto_res + CT_CRYPTO_CORE_CONTROL_OFFSET);
    _DPRINT("Control register: 0x%08X\n",
           readl(engine->crypto_res + CT_CRYPTO_CORE_CONTROL_OFFSET));

    _DPRINT("Crypto tx count: %d\n",readl(engine->crypto_res + CT_CRYPTO_CORE_TX_COUNT_OFFSET));
    _DPRINT("Crypto rx count: %d\n",readl(engine->crypto_res + CT_CRYPTO_CORE_RX_COUNT_OFFSET));
    _DPRINT("Crypto state register: %d\n",readl(engine->crypto_res + CT_CRYPTO_CORE_STATE_OFFSET));

    writel(ctx->hash_key_len,engine->crypto_res + CT_CRYPTO_CORE_AUTHENKEY_LENGTH_OFFSET);
    _DPRINT("Hash key len: %d\n",readl(engine->crypto_res + CT_CRYPTO_CORE_AUTHENKEY_LENGTH_OFFSET));

    //set hash key registers
    u32_val = (u32 *)ctx->hash_ctx;
    len = (sizeof(ctx->hash_ctx))/sizeof(u32);
    for (i = 0,offs = 0;i < len; i++,offs += sizeof(u32)) {
        writel(*u32_val,engine->crypto_res + CT_CRYPTO_CORE_AUTHENKEY_OFFSET + offs);
//        DPRINT("authen key[%d]: 0x%08X\n",i,
//               readl(engine->crypto_res + CT_CRYPTO_CORE_AUTHENKEY_OFFSET + offs));
        u32_val++;
    }

    //set cipher key registers
    u32_val = (u32 *)ctx->cipher_key;
    len = (ctx->cipher_key_len + (sizeof(u32) -1))/sizeof(u32);
    for (i = 0, offs = 0;i < len; i++, offs += sizeof(u32)) {
        writel(*u32_val,engine->crypto_res + CT_CRYPTO_CORE_ENCKEY_OFFSET + offs);
//        DPRINT("cipher key[%d]: 0x%08X\n",i,
//               readl(engine->crypto_res + CT_CRYPTO_CORE_ENCKEY_OFFSET + offs));
        u32_val++;
    }
    writel(ctx->cipher_key_len,engine->crypto_res + CT_CRYPTO_CORE_ENCKEY_LENGTH_OFFSET);
    _DPRINT("cipher key length: %d\n",
           readl(engine->crypto_res + CT_CRYPTO_CORE_ENCKEY_LENGTH_OFFSET));


    //set iv size register
    writel(ivsize,engine->crypto_res + CT_CRYPTO_CORE_IVSIZE_OFFSET);
    _DPRINT("ivsize length: %d\n",
           readl(engine->crypto_res + CT_CRYPTO_CORE_IVSIZE_OFFSET));

    //set associated length register
    writel(aead_req->req->assoclen,engine->crypto_res + CT_CRYPTO_CORE_ASSOC_LENGTH_OFFSET);
    _DPRINT("association length: %d\n",
           readl(engine->crypto_res + CT_CRYPTO_CORE_ASSOC_LENGTH_OFFSET));

    //set crypto length register
    crypt_len = aead_req->req->cryptlen;
#if 0
    if (aead_req->giv)
        crypt_len += aead_req->giv_len;
#endif
    if (!aead_req->is_encrypt)
        crypt_len -= ctx->auth_size;

    writel(crypt_len,
           engine->crypto_res + CT_CRYPTO_CORE_CRYPTO_LENGTH_OFFSET);
    _DPRINT("cryptlen register: %d\n",
           readl(engine->crypto_res + CT_CRYPTO_CORE_CRYPTO_LENGTH_OFFSET));

    //set auth_size register
    writel(ctx->auth_size, engine->crypto_res + CT_CRYPTO_CORE_AUTH_SIZE_OFFSET);
    _DPRINT("authentication register: %d\n",
           readl(engine->crypto_res + CT_CRYPTO_CORE_AUTH_SIZE_OFFSET));

    _DPRINT("Crypto state register: %d\n",readl(engine->crypto_res + CT_CRYPTO_CORE_STATE_OFFSET));

    //submit and flush dma requests
    if (aead_req->req->assoclen > 0) {
        centic_crypto_submit_dma_request(&aead_req->tx_dma_assoc_request);
    }

    centic_crypto_submit_dma_request(&aead_req->tx_dma_iv_request);
#if 0
    if (aead_req->giv && aead_req->giv_len > 0) {
        centic_crypto_submit_dma_request(&aead_req->tx_dma_giv_request);
        centic_crypto_submit_dma_request(&aead_req->rx_dma_giv_request);
    }
#endif

    if (aead_req->tx_dma_data_request.nents > 0
        && aead_req->rx_dma_data_request.nents ) {
        centic_crypto_submit_dma_request(&aead_req->tx_dma_data_request);
        centic_crypto_submit_dma_request(&aead_req->rx_dma_data_request);
    }

    centic_crypto_defer_flush_dma_request(engine);

    DPRINT("Exit\n");

    return;
}

struct centic_crypto_alg centic_crypto_ipsec_algs[] = {
    {
        .alg = {
            .cra_name = "authenc(hmac(sha256),cbc(aes))",
            .cra_driver_name = "authenc-hmac-sha256-cbc-aes-centic-crypto",
            .cra_priority = CENTIC_CRYPTO_ALG_PRIORITY,
            .cra_flags = CRYPTO_ALG_TYPE_AEAD |
                    CRYPTO_ALG_ASYNC |
                    CRYPTO_ALG_KERN_DRIVER_ONLY,
            .cra_blocksize = AES_BLOCK_SIZE,
            .cra_ctxsize = sizeof(struct centic_crypto_aead_tfm_ctx),
            .cra_type = &crypto_aead_type,
            .cra_module = THIS_MODULE,
            .cra_aead = {
                .setkey = centic_crypto_aead_setkey,
                .setauthsize = centic_crypto_aead_setauthsize,
                .encrypt = centic_crypto_aead_encrypt,
                .decrypt = centic_crypto_aead_decrypt,
                .givencrypt = centic_crypto_aead_givencrypt,
                .ivsize = AES_BLOCK_SIZE,
                .maxauthsize = SHA256_DIGEST_SIZE,
            },
            .cra_init = centic_crypto_aead_cra_init,
            .cra_exit = centic_crypto_aead_cra_exit,
        }
    }
};

static irqreturn_t axi_dma_intr_handler(int irq, void *data)
{
    struct centic_crypto_engine *engine = (struct centic_crypto_engine *)data;
    u32 status;
    unsigned long flags;

    DPRINT("Enter\n");

    spin_lock_irqsave(&engine->dma_lock, flags);
    //store status register to tasklet_handler process
    status = readl(engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_STATUS_OFFSET);
#ifdef DEBUG
    if (status & AXI_DMA_SR_IOC_INT_MASK) {
        printk("======= Tx interrupt %d\n",__LINE__);
    }
#endif
    if (status & AXI_DMA_SR_ERR_INT_MASK){
        printk("======= Err %s - line: %d\n",__FUNCTION__,__LINE__);
        engine->tx_dma_err_count++;
    }
    //clean all interrupt flags
    writel(status,engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_STATUS_OFFSET);

    status = readl(engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_STATUS_OFFSET);
#ifdef DEBUG
    if (status & AXI_DMA_SR_IOC_INT_MASK) {
        printk("======= Rx interrupt %d\n",__LINE__);
    }
#endif
    if ( status & AXI_DMA_SR_ERR_INT_MASK){
        printk("======== Err %s - line: %d\n",__FUNCTION__,__LINE__);
        engine->rx_dma_err_count++;
    }

    writel(status,engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_STATUS_OFFSET);

    spin_unlock_irqrestore(&engine->dma_lock, flags);

    centic_crypto_defer_flush_dma_request(engine);    

    DPRINT("Exit\n");

    return IRQ_HANDLED;
}

static void axi_dma_interrupt_tasklet_handler(unsigned long data)
{
    struct centic_crypto_dma_request *req,*next;
    int need_flush;
    struct centic_crypto_engine *engine = (struct centic_crypto_engine *)data;
    unsigned long flags;
    struct list_head tx_completed_list;
    struct list_head rx_completed_list;

    DPRINT("Enter\n");
    // tx_dma_check_complete_and_flush
    spin_lock_irqsave(&engine->dma_lock, flags);


    _DPRINT("Crypto tx count: %d\n",readl(engine->crypto_res + CT_CRYPTO_CORE_TX_COUNT_OFFSET));
    _DPRINT("Crypto rx count: %d\n",readl(engine->crypto_res + CT_CRYPTO_CORE_RX_COUNT_OFFSET));
    _DPRINT("Crypto state register: %d\n",readl(engine->crypto_res + CT_CRYPTO_CORE_STATE_OFFSET));
    _DPRINT("HMAC state: %d\n",readl(engine->crypto_res + CT_CRYPTO_HMAC_STATE_OFFSET));

    INIT_LIST_HEAD(&tx_completed_list);
    INIT_LIST_HEAD(&rx_completed_list);

    need_flush = 0;

    list_for_each_entry_safe(req,next,&engine->tx_dma_req_processing,entry) {
        struct axi_dma_sg_desc_wrapper *sg_cur,*sg_next;
        list_for_each_entry_safe(sg_cur,sg_next,&req->sg_desc_list,req_entry) {
            if (sg_cur->hw.status & CENTIC_CRYPTO_DMA_SG_DESC_CR_COMPLETED) {
                if (req->sg_desc_list.prev == &sg_cur->req_entry) {
                    list_del(&sg_cur->req_entry);
                    sg_cur->flags = 0;
                    if (req->sgoff  >= req->nents)
                    {
            #if 0
                        if ((sg_cur->hw.status & AXI_DMA_SG_DESC_CR_LEN_MASK) !=
                                (sg_cur->hw.control & AXI_DMA_SG_DESC_CR_LEN_MASK)) {
                            DPRINT("tx ==== Bug at here ====: %08X\n",sg_cur->hw.status);
                        }
            #endif
                        list_move(&req->entry,&tx_completed_list);
                        req->flags = (req->flags & (~CT_DMA_REQ_FLAGS_STATE_MASK))|CT_DMA_REQ_FLAGS_STATE_COMPLETE;
                        engine->tx_dma_processing_count--;
                    }
                    else {
                        centic_crypto_flush_dma_request(req);
                    }
                }
                else {
                    _DPRINT("Tx [%p]: remove sg from dma request\n",sg_cur);
                    list_del(&sg_cur->req_entry);
                    sg_cur->flags = 0;
                }
            }
            else
                break;
        }
    }

    if (!list_empty(&engine->tx_dma_req_processing)) {
        need_flush = 1;
    }
    else if (!list_empty(&engine->tx_dma_req_pending)) {
        centic_crypto_flush_tx_dma_requests(engine);
        need_flush = 1;
    }

    list_for_each_entry_safe(req,next,&engine->rx_dma_req_processing,entry) {
        struct axi_dma_sg_desc_wrapper *sg_cur,*sg_next;
        list_for_each_entry_safe(sg_cur,sg_next,&req->sg_desc_list,req_entry) {
            if (sg_cur->hw.status & CENTIC_CRYPTO_DMA_SG_DESC_CR_COMPLETED) {
                if (req->sg_desc_list.prev == &sg_cur->req_entry) {
                    list_del(&sg_cur->req_entry);
                    sg_cur->flags = 0;
                    if (req->sgoff  >= req->nents)
                    {
            #if 0
                        if ((sg_cur->hw.status & AXI_DMA_SG_DESC_CR_LEN_MASK) !=
                                (sg_cur->hw.control & AXI_DMA_SG_DESC_CR_LEN_MASK)) {
                            DPRINT("rx ==== Bug at here ====: %08X\n",sg_cur->hw.status);
                        }
            #endif
                        _DPRINT("Move to rx complete list\n");
                        list_move(&req->entry,&rx_completed_list);
                        req->flags = (req->flags & (~CT_DMA_REQ_FLAGS_STATE_MASK))|CT_DMA_REQ_FLAGS_STATE_COMPLETE;
                        engine->rx_dma_processing_count--;
                    }
                    else {
                        centic_crypto_flush_dma_request(req);
                    }
                }
                else {
                    _DPRINT("Rx [%p]: remove sg from dma request\n",sg_cur);
                    list_del(&sg_cur->req_entry);
                    sg_cur->flags = 0;
                }
            }
            else
                break;
        }
    }

    if (!list_empty(&engine->rx_dma_req_processing)) {
        need_flush = 1;
    }
    else if (!list_empty(&engine->rx_dma_req_pending)) {
        centic_crypto_flush_rx_dma_requests(engine);
        need_flush = 1;
    }

    spin_unlock_irqrestore(&engine->dma_lock, flags);

    list_for_each_entry_safe(req,next,&tx_completed_list,entry){
        engine->tx_dma_completed_count++;
        if (req->complete)
            req->complete(req);
    }

    list_for_each_entry_safe(req,next,&rx_completed_list,entry){
        engine->rx_dma_completed_count++;
        if (req->complete)
            req->complete(req);
    }

    if (need_flush)
        centic_crypto_defer_flush_dma_request(engine);

    DPRINT("Exit - tx completed count: %d - rx completed count: %d\n",engine->tx_dma_completed_count,
           engine->rx_dma_completed_count);
}

static int  centic_crypto_flush_dma_request(struct centic_crypto_dma_request *req)
{
    // NOTE: Remember use semaphore before call this function

    int count = 0;
    int i;
    struct scatterlist *sg_cur;
    struct axi_dma_sg_desc_wrapper *cur,*chain_last;
    struct centic_crypto_engine *engine = req->engine;
    int direction;

    direction = (req->flags & CT_DMA_REQ_FLAGS_TO_DEVICE_DIRECTION);

    DPRINT("Enter - [%s] -> partial status: %d - req->sgoff: %d\n",
           (direction ? "tx" : "rx"),direction ? engine->tx_dma_partial_processing:engine->rx_dma_partial_processing,req->sgoff);

#if 0
    if (!req->sgoff && req->flags & CT_DMA_REQ_FLAGS_SOF) {
        startframe = 1;
    }
#endif

    cur = direction ? engine->tx_cur_sg_desc: engine->rx_cur_sg_desc;

    INIT_LIST_HEAD(&req->sg_desc_list);

    _DPRINT("Cur: %p - Cur->flags: %d\n",cur,cur->flags);

    if (!(cur->flags & AXI_DMA_SG_WRAPPER_BUSY)) {
        for_each_sg(req->sg, sg_cur, req->nents, i) {
            if (i >= req->sgoff) {
                count++;
                cur->hw.buf_addr = sg_dma_address(sg_cur);
                //whether we need check sg_dma_len at here to make sure the size is not zero
                _DPRINT("[%s] - SG Len: %d\n",direction ? "tx":"rx", sg_dma_len(sg_cur));

                cur->hw.control = sg_dma_len(sg_cur) & AXI_DMA_SG_DESC_CR_LEN_MASK;
                cur->hw.status = 0;

                if (direction)
                    cur->hw.control|=AXI_DMA_SG_DESC_CR_SOF_MASK;

                cur->flags = AXI_DMA_SG_WRAPPER_BUSY;

                list_add_tail(&cur->req_entry,&req->sg_desc_list);

                //print_axi_sg_description_content(cur);

                cur = list_first_entry(&cur->ring_entry,struct axi_dma_sg_desc_wrapper,ring_entry);

                _DPRINT("Cur: %p - Cur->flags: %d\n",cur,cur->flags);

                if (cur->flags & AXI_DMA_SG_WRAPPER_BUSY) {
                    printk(" ==== Not free SG - [%s] -> Cur: %p - Cur->flags: %d\n",
                           (direction ? "tx" : "rx"),cur,cur->flags);
                    i++;
                    break;
                }

            }
        }
        if (direction)
            engine->tx_cur_sg_desc = cur;
        else
            engine->rx_cur_sg_desc = cur;
    }
    else {
        printk(" Not free SG - [%s] -> Cur: %p - Cur->flags: %d\n",
               (direction ? "tx" : "rx"),cur,cur->flags);
    }



    if (count > 0) { //flushed partial or overall request
        req->sgoff = i;
        chain_last = list_last_entry(&req->sg_desc_list,struct axi_dma_sg_desc_wrapper,req_entry);
        chain_last->hw.control |= AXI_DMA_SG_DESC_CR_EOF_MASK;

        if (direction) {
            writel(chain_last->sg_desc_dma_addr,
                   engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_TDESC_OFFSET);

            engine->tx_dma_partial_processing = (req->sgoff >= req->nents) ? 0 : 1;
        }
        else {
            writel(chain_last->sg_desc_dma_addr,
                   engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_TDESC_OFFSET);

            engine->rx_dma_partial_processing = (req->sgoff >= req->nents) ? 0 : 1;
        }
    }

    DPRINT("Exit - [%s] -> partial status: %d - req->sgoff: %d\n",
           (direction ? "tx" : "rx"),direction ? engine->tx_dma_partial_processing :
                    engine->rx_dma_partial_processing,req->sgoff);

    return count;
}

static int centic_crypto_flush_tx_dma_requests(struct centic_crypto_engine *engine) {
    struct centic_crypto_dma_request *req,*next;
    int flush_count = 0;
    DPRINT("Enter - pending count: %d - processing count: %d\n",engine->tx_dma_pending_count,
           engine->tx_dma_processing_count);

    if (engine->tx_dma_partial_processing){
        return 0;
    }

    list_for_each_entry_safe(req,next,&engine->tx_dma_req_pending,entry) {
        int count = 0;
            if (engine->tx_dma_partial_processing){
                break;
            }
            count = centic_crypto_flush_dma_request(req);
            if (count){
                flush_count++;

                list_move_tail(&req->entry,&engine->tx_dma_req_processing);

                req->flags = (req->flags & (~CT_DMA_REQ_FLAGS_STATE_MASK))|CT_DMA_REQ_FLAGS_STATE_PROCESSING;

                engine->tx_dma_processing_count++;
                if (engine->tx_dma_processing_count > engine->tx_max_dma_processing_count)
                    engine->tx_max_dma_processing_count = engine->tx_dma_processing_count;

                engine->tx_dma_pending_count--;
            }
            else
                break;
    }

    DPRINT("Exit - pending count: %d - processing count: %d \n",
           engine->tx_dma_pending_count, engine->tx_dma_processing_count);

    return flush_count;
}

static int centic_crypto_flush_rx_dma_requests(struct centic_crypto_engine *engine) {
    struct list_head *cur,*next;
    int flush_count = 0;

    DPRINT("Enter - pending count: %d - processing count: %d\n",engine->rx_dma_pending_count,
           engine->rx_dma_processing_count);
    if (engine->rx_dma_partial_processing){
        return 0;
    }

    list_for_each_safe(cur,next,&engine->rx_dma_req_pending) {
        int count = 0;
        struct centic_crypto_dma_request *req = container_of(cur,struct centic_crypto_dma_request,entry);
            if (engine->rx_dma_partial_processing){
                break;
            }
            count = centic_crypto_flush_dma_request(req);
            if (count) {
                flush_count++;

                list_move_tail(cur,&engine->rx_dma_req_processing);

                req->flags = (req->flags & (~CT_DMA_REQ_FLAGS_STATE_MASK))|CT_DMA_REQ_FLAGS_STATE_PROCESSING;

                engine->rx_dma_processing_count++;
                if (engine->rx_dma_processing_count > engine->rx_max_dma_processing_count)
                    engine->rx_max_dma_processing_count = engine->rx_dma_processing_count;

                engine->rx_dma_pending_count--;
            }
            else
                break;
    }
    DPRINT("Exit - pending count: %d - processing count: %d \n",
           engine->rx_dma_pending_count, engine->rx_dma_processing_count);

    return flush_count;
}

static int centic_crypto_submit_dma_request(struct centic_crypto_dma_request *req) {
    struct centic_crypto_engine *engine = req->engine;
    unsigned long flags;
    DPRINT("Enter\n");
    spin_lock_irqsave(&engine->dma_lock, flags);
    if (req->flags & CT_DMA_REQ_FLAGS_TO_DEVICE_DIRECTION) {
       req->sgoff = 0;
       req->flags = (req->flags & (~CT_DMA_REQ_FLAGS_STATE_MASK))|CT_DMA_REQ_FLAGS_STATE_PENDING;
       list_add_tail(&req->entry,&engine->tx_dma_req_pending);
       engine->tx_dma_pending_count++;
    }
    else {
        req->sgoff = 0;
        req->flags = (req->flags & (~CT_DMA_REQ_FLAGS_STATE_MASK))|CT_DMA_REQ_FLAGS_STATE_PENDING;
        list_add_tail(&req->entry,&engine->rx_dma_req_pending);
        engine->rx_dma_pending_count++;
    }
    spin_unlock_irqrestore(&engine->dma_lock, flags);
    DPRINT("Exit\n");
    return 0;
}

static int centic_crypto_init_engine_resources(struct centic_crypto_engine *engine) {
    struct resource *res;
    struct device_node *axi_dma_node;
    u32 axidmares[2];
    struct resource axi_dma_res;
    struct platform_device *pdev = container_of(engine->devp,struct platform_device,dev);
    int err;

    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    engine->crypto_res = devm_ioremap_resource(&pdev->dev, res);
    if (IS_ERR(engine->crypto_res))
        return PTR_ERR(engine->crypto_res);
    DPRINT("Centic-Crypto resource info [%X] [%d]\n",res->start,(res->end - res->start)+1);

    //reset Centic Crypto Core
#ifndef TEST_DMA
    writel(CT_CRYPTO_CORE_CR_RESET_MASK,engine->crypto_res + CT_CRYPTO_CORE_CONTROL_OFFSET);
    mdelay(10);
    writel(0,engine->crypto_res + CT_CRYPTO_CORE_CONTROL_OFFSET);
#endif

    axi_dma_node = of_find_node_by_name(NULL,"axi-dma");
    if (axi_dma_node == NULL) {
        printk(KERN_ERR"The platform doesn't have any axi-dma core\n");
        return -1;
    }

    if (!of_device_is_compatible(axi_dma_node,"xlnx,axi-dma-6.02.a")) {
        printk(KERN_ERR"The platform doesn't have any compatible axi-dma core\n");
        return -1;
    }

    if (of_property_read_u32_array(axi_dma_node,"reg",axidmares,2) != 0) {
        printk(KERN_ERR"Reg info of axi dma does not exists\n");
        return -1;
    }
    DPRINT("Axi-dma resource info [%X] [%d]\n",axidmares[0],axidmares[1]);

    engine->tx_dma_irq = irq_of_parse_and_map(axi_dma_node,0);
    if (!engine->tx_dma_irq) {
        printk(KERN_ERR"Interrupt info of axi dma does not exists\n");
        return -1;
    }

    engine->rx_dma_irq = irq_of_parse_and_map(axi_dma_node,1);
    if (!engine->rx_dma_irq) {
        printk(KERN_ERR"Interrupt info of axi dma does not exists\n");
        return -1;
    }

    DPRINT("Axi-dma Interrupt Request info [%X]\n",engine->dma_irq);
    err = devm_request_irq(&pdev->dev, engine->tx_dma_irq, axi_dma_intr_handler,
                   IRQF_SHARED,"tx-axi-dma-interrupt-controller", engine);
    if (err) {
        dev_err(&pdev->dev, "unable to request IRQ\n");
        return err;
    }

    err = devm_request_irq(&pdev->dev, engine->rx_dma_irq, axi_dma_intr_handler,
                   IRQF_SHARED,"tx-axi-dma-interrupt-controller", engine);
    if (err) {
        dev_err(&pdev->dev, "unable to request IRQ\n");
        return err;
    }


    axi_dma_res = (struct resource)DEFINE_RES_MEM_NAMED(axidmares[0],axidmares[1],"axi-dma-res");
    engine->dma_res = devm_ioremap_resource(&pdev->dev, &axi_dma_res);
    if (IS_ERR(engine->dma_res))
        return PTR_ERR(engine->dma_res);

    return 0;
}

static void centic_crypto_clean_engine_resources(struct centic_crypto_engine *engine) {
#ifndef TEST_DMA
    writel(CT_CRYPTO_CORE_CR_RESET_MASK,engine->crypto_res + CT_CRYPTO_CORE_CONTROL_OFFSET);
    mdelay(10);
    writel(0,engine->crypto_res + CT_CRYPTO_CORE_CONTROL_OFFSET);
#endif
    devm_free_irq(engine->devp,engine->tx_dma_irq,engine);
    devm_free_irq(engine->devp,engine->rx_dma_irq,engine);
}


static int centic_crypto_register_crypto_alg(struct centic_crypto_engine *engine) {
#ifndef TEST_DMA
    int num_algs = sizeof(centic_crypto_ipsec_algs) / sizeof(struct centic_crypto_alg);
    int err;
    int ret = -1;
#endif
    int i;
    struct centic_crypto_aead_request *aead_req_pool;

    INIT_LIST_HEAD(&engine->crypto_aead_req_pool);

    aead_req_pool = (struct centic_crypto_aead_request *)devm_kzalloc(engine->devp,
        sizeof(struct centic_crypto_aead_request) * CENTIC_CRYPTO_AEAD_FIFO_SIZE, GFP_KERNEL);
    if (aead_req_pool == NULL)
        return -ENOMEM;

    for (i = 0; i<CENTIC_CRYPTO_AEAD_FIFO_SIZE; i++) {
        list_add_tail(&aead_req_pool->entry,&engine->crypto_aead_req_pool);
        aead_req_pool++;
    }

    INIT_LIST_HEAD(&engine->crypto_aead_req_pending);
    INIT_LIST_HEAD(&engine->crypto_aead_req_processing);
    INIT_LIST_HEAD(&engine->crypto_aead_req_completed);

    tasklet_init(&engine->aead_request_flush_tasklet,
                 aead_request_flush_tasklet_handler,
             (unsigned long)engine);

    INIT_LIST_HEAD(&engine->registered_algs);
#ifndef TEST_DMA
    for (i = 0;i<num_algs; i++) {
        centic_crypto_ipsec_algs[i].engine = engine;
        err = crypto_register_alg(&centic_crypto_ipsec_algs[i].alg);
        if (!err) {
                list_add_tail(&centic_crypto_ipsec_algs[i].entry,
                          &engine->registered_algs);
                ret = 0;
        }
        if (err)
            dev_err(engine->devp, "failed to register alg \"%s\"\n",
                centic_crypto_ipsec_algs[i].alg.cra_name);
        else
            dev_info(engine->devp, "registered alg \"%s\"\n",
                centic_crypto_ipsec_algs[i].alg.cra_name);
    }
    return ret;
#else
    return 0;
#endif

}

static void centic_crypto_unregister_crypto_alg(struct centic_crypto_engine *engine) {
    struct centic_crypto_alg *alg, *next;

    list_for_each_entry_safe(alg, next, &engine->registered_algs, entry) {
        list_del(&alg->entry);
        crypto_unregister_alg(&alg->alg);
    }

}

static int centic_crypto_init_dma_resources(struct centic_crypto_engine *engine) {

    int i;
    dma_addr_t tmp3,tmp4;

    struct axi_dma_sg_desc_wrapper *tmp1,*tmp2;

    INIT_LIST_HEAD(&engine->tx_dma_req_pending);
    INIT_LIST_HEAD(&engine->tx_dma_req_processing);

    INIT_LIST_HEAD(&engine->rx_dma_req_pending);
    INIT_LIST_HEAD(&engine->rx_dma_req_processing);

    engine->sg_desc_pool = dma_pool_create("ct-cryp-dma-pool", engine->devp,
        CENTIC_CRYPTO_MAX_NUM_SG_DESC * sizeof(struct axi_dma_sg_desc_wrapper),64,0);
    if (!engine->sg_desc_pool)
        return -ENOMEM;

    engine->tx_first_sg_desc = tmp1 = dma_pool_alloc(engine->sg_desc_pool,GFP_KERNEL,&tmp3);
    engine->rx_first_sg_desc = tmp2 = dma_pool_alloc(engine->sg_desc_pool,GFP_KERNEL,&tmp4);

    if (engine->tx_first_sg_desc == NULL || engine->rx_first_sg_desc == NULL) {
        goto failed_free_dma_resources;
    }

    for (i = 0;i<CENTIC_CRYPTO_MAX_NUM_SG_DESC;i++) {
        tmp1->sg_desc_dma_addr = tmp3;
        tmp3 += sizeof(struct axi_dma_sg_desc_wrapper);

        tmp2->sg_desc_dma_addr = tmp4;
        tmp4 += sizeof(struct axi_dma_sg_desc_wrapper);

        tmp1->hw.buf_addr = 0;
        tmp1->hw.status = 0x80000000;
        tmp1->flags = 0;
        INIT_LIST_HEAD(&tmp1->req_entry);

        tmp2->hw.buf_addr = 0;
        tmp2->hw.status = 0x80000000;
        tmp2->flags = 0;
        INIT_LIST_HEAD(&tmp2->req_entry);

        if (engine->tx_first_sg_desc == tmp1) {
            INIT_LIST_HEAD(&engine->tx_first_sg_desc->ring_entry);
        }
        else {
            list_add_tail(&tmp1->ring_entry,&engine->tx_first_sg_desc->ring_entry);
        }

        if (engine->rx_first_sg_desc == tmp2) {
            INIT_LIST_HEAD(&engine->rx_first_sg_desc->ring_entry);
        }
        else {
            list_add_tail(&tmp2->ring_entry,&engine->rx_first_sg_desc->ring_entry);
        }

        if (i < (CENTIC_CRYPTO_MAX_NUM_SG_DESC - 1)) {
            tmp1->hw.next_desc = tmp3;
            tmp2->hw.next_desc = tmp4;
        }
        else {
            tmp1->hw.next_desc = engine->tx_first_sg_desc->sg_desc_dma_addr;
            tmp2->hw.next_desc = engine->rx_first_sg_desc->sg_desc_dma_addr;
        }

        tmp1++;
        tmp2++;
    }

    engine->tx_cur_sg_desc = engine->tx_first_sg_desc;
    engine->rx_cur_sg_desc = engine->rx_first_sg_desc;

    tasklet_init(&engine->axi_dma_interrupt_tasklet,
                 axi_dma_interrupt_tasklet_handler,
             (unsigned long)engine);

    //Reset AXI DMA MM2S
    writel(readl(engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_CONTROL_OFFSET) | AXI_DMA_CR_RESET_MASK,
           engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_CONTROL_OFFSET);
    //Reset AIX DMA S2MM
    writel(readl(engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_CONTROL_OFFSET) | AXI_DMA_CR_RESET_MASK,
           engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_CONTROL_OFFSET);

    mdelay(10);

    if (readl(engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_CONTROL_OFFSET) & AXI_DMA_CR_RESET_MASK) {
        //reset fail so exit with error
        printk(KERN_ERR"Reseting axi mm2s dma core failed\n");
        goto failed_free_dma_resources;
    }
    if (readl(engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_CONTROL_OFFSET) & AXI_DMA_CR_RESET_MASK) {
        //reset fail so exit with error
        printk(KERN_ERR"Reseting axi s2mm dma core failed\n");
        goto failed_free_dma_resources;
    }

    //check sg mode, centic-crypto only supportes Scatter Gather mode
    if ((readl(engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_STATUS_OFFSET) & AXI_DMA_SR_SG_MASK) == 0){
        printk(KERN_ERR"The axi dma cores do not support Scatter Gather\n");
        goto failed_free_dma_resources;
    }

    //initialize current descriptor register

    writel(engine->tx_first_sg_desc->sg_desc_dma_addr,engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_CDESC_OFFSET);
    writel(engine->rx_first_sg_desc->sg_desc_dma_addr,engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_CDESC_OFFSET);

    writel(engine->tx_first_sg_desc->sg_desc_dma_addr,engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_TDESC_OFFSET);
    writel(engine->rx_first_sg_desc->sg_desc_dma_addr,engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_TDESC_OFFSET);


    //enable IOC & Err interrupts and run dma
    writel(readl(engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_CONTROL_OFFSET)
           | AXI_DMA_CR_RUNSTOP_MASK | AXI_DMA_CR_EN_IRQ_IOC_MASK | AXI_DMA_CR_EN_IRQ_ERR_MASK,
           engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_CONTROL_OFFSET);

    writel(readl(engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_CONTROL_OFFSET)
           | AXI_DMA_CR_RUNSTOP_MASK | AXI_DMA_CR_EN_IRQ_IOC_MASK | AXI_DMA_CR_EN_IRQ_ERR_MASK,
           engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_CONTROL_OFFSET);


    //currently, DMA engines is really in paused status
    // any writing activities into trail descriptor registers after that will really start dma engines

    return 0;
failed_free_dma_resources:
    if (engine->tx_first_sg_desc) dma_pool_free(engine->sg_desc_pool,engine->tx_first_sg_desc,engine->tx_first_sg_desc->sg_desc_dma_addr);
    if (engine->rx_first_sg_desc) dma_pool_free(engine->sg_desc_pool,engine->rx_first_sg_desc,engine->rx_first_sg_desc->sg_desc_dma_addr);
    if (engine->sg_desc_pool) dma_pool_destroy(engine->sg_desc_pool);

    return -ENOMEM;

}

static void centic_crypto_clean_dma_resources(struct centic_crypto_engine *engine) {
    //Reset AXI DMA MM2S
    writel(readl(engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_CONTROL_OFFSET) | AXI_DMA_CR_RESET_MASK,
           engine->dma_res + AXI_DMA_MM2S_OFFSET + AXI_DMA_CONTROL_OFFSET);
    //Reset AIX DMA S2MM
    writel(readl(engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_CONTROL_OFFSET) | AXI_DMA_CR_RESET_MASK,
           engine->dma_res + AXI_DMA_S2MM_OFFSET + AXI_DMA_CONTROL_OFFSET);

    mdelay(10);

    tasklet_kill(&engine->axi_dma_interrupt_tasklet);

    if (engine->tx_first_sg_desc) dma_pool_free(engine->sg_desc_pool,engine->tx_first_sg_desc,engine->tx_first_sg_desc->sg_desc_dma_addr);
    if (engine->rx_first_sg_desc) dma_pool_free(engine->sg_desc_pool,engine->rx_first_sg_desc,engine->rx_first_sg_desc->sg_desc_dma_addr);
    if (engine->sg_desc_pool) dma_pool_destroy(engine->sg_desc_pool);
}



static int __init centic_crypto_probe(struct platform_device * pdev)
{
    dev_t devnum;
    int err;
    struct centic_crypto_engine *engine = NULL;
    DPRINT("centic_crypto_probe - %d\n",HZ);

    engine = devm_kzalloc(&pdev->dev,sizeof(struct centic_crypto_engine),GFP_KERNEL);
    if (engine == NULL) {
        printk(KERN_ERR"Not enought memory\n");
        return -1;
    }
    sema_init(&engine->sem,1);
    spin_lock_init(&engine->dma_lock);
    spin_lock_init(&engine->crypto_lock);

    engine->devp = &pdev->dev;

    err = alloc_chrdev_region(&devnum,0,1,"centic-crypto");
    if (err){
        printk(KERN_ERR"Error %d getting device number\n",err);
        return -ENOMEM;
    }

    cdev_init(&engine->cdev,&centic_crypto_file_ops);

    engine->cdev.owner = THIS_MODULE;
    engine->cdev.ops = &centic_crypto_file_ops;
    kobject_set_name(&(engine->cdev.kobj),"centic-crypto");
    err = cdev_add(&engine->cdev,devnum,1);
    if (err) {
        printk(KERN_ERR"Error %d adding char device\n", err);
        goto fail_free_0;
    }

    if ((err = centic_crypto_init_engine_resources(engine))) {
        goto fail_free_1;
    }

    if ((err = centic_crypto_init_dma_resources(engine))) {
        goto fail_free_2;
    }

    if ((err = centic_crypto_register_crypto_alg(engine))) {
        goto fail_free_3;
    }

#ifdef SPEED_STATISTIC_ANALYSIS
    if ((err = centic_crypto_proc_init(engine))) {
        goto fail_free_4;
    }
#endif

    platform_set_drvdata(pdev, engine);

    //device_create_file(engine->devp,)

    return 0;
#ifdef SPEED_STATISTIC_ANALYSIS
fail_free_4:
    centic_crypto_proc_release(engine);
#endif
fail_free_3:
    centic_crypto_unregister_crypto_alg(engine);
fail_free_2:
    centic_crypto_clean_dma_resources(engine);
fail_free_1:
    centic_crypto_clean_engine_resources(engine);
fail_free_0:
    unregister_chrdev_region(devnum,1);
    return err;

}

static int centic_crypto_remove(struct platform_device * pdev)
{
    struct centic_crypto_engine *engine = platform_get_drvdata(pdev);
    DPRINT("centic_crypto_remove \n");

    tasklet_kill(&engine->aead_request_flush_tasklet);

#ifdef SPEED_STATISTIC_ANALYSIS
    centic_crypto_proc_release(engine);
#endif

    centic_crypto_unregister_crypto_alg(engine);

    centic_crypto_clean_dma_resources(engine);

    centic_crypto_clean_engine_resources(engine);

    unregister_chrdev_region(engine->cdev.dev,1);

    return 0;
}

static struct platform_driver centic_crypto_plat_driver = {
.driver		= {
    .name	= "centic-crypto",
    .owner  = THIS_MODULE,
    .of_match_table	= of_match_ptr(centic_crypto_of_id_table),
    },
.id_table	= centic_crypto_id_table,
.remove		= centic_crypto_remove,
};

module_platform_driver_probe(centic_crypto_plat_driver,centic_crypto_probe);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luong Phan");
MODULE_VERSION("1.0.0");

#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>


#include <linux/slab.h>
//    void *kmalloc(size_t size, int flags);


#include <linux/vmalloc.h>
//void *vmalloc(unsigned long size);
//void vfree(void * addr);
//void *ioremap(unsigned long offset, unsigned long size);
//void iounmap(void * addr);

#include <linux/atomic.h>

#include <linux/completion.h>

#include <linux/interrupt.h>
//struct tasklet_struct {
//      /* ... */
//      void (*func)(unsigned long);
//      unsigned long data;
//};

//void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data);
//void tasklet_schedule(struct tasklet_struct *t);
static struct tasklet_struct tasklet;

#///////////////////////////////////////////////////////////////////
static struct completion comp;

static int complete_read(void)
{
    printk(KERN_ALERT "read thread ... \n");
    wait_for_completion(&comp); /* standby here and continue when another call complete() function */
    printk(KERN_ALERT "awoken \n");
    return 1; /* EOF */
}

static int complete_write(void)
{
    printk(KERN_ALERT "write thread ... \n");
    complete(&comp);
    printk(KERN_ALERT "awakening the readers...\n");
    return 1; /* succeed, to avoid retrial */
}

static void tasklet_handle(unsigned long data){
    float *pdata = (float*)data;
    *pdata++;

    printk(KERN_ALERT "tasklet_handle \n");
    return;
}



typedef struct list_item_t{
    struct list_head entry;
    int data;
}list_item_t;
#define LIST_MAX_ITEM 10


static int __init hello_init(void)
{
    printk(KERN_ALERT "Khoi tao thanh cong\n");

    /* LIKELY & UNLIKELY */
#if 0
    int *p = NULL;
    p = (int*)kmalloc(sizeof(int), GFP_KERNEL);

    if (unlikely(p==NULL)){
        printk(KERN_ALERT "unlikely(p) \n");
    }

    if (likely(!p)){
        printk(KERN_ALERT "likely(p) \n");
    }

    if(p){
        kfree(p);
        printk(KERN_ALERT "kfree(p) \n");
    }
#endif

    /* AUTOMIC */
#if 0
    atomic_t ref_count;

    atomic_set(&ref_count,2);

    printk(KERN_ALERT "atomic_read(ref_count) = %d \n", atomic_read(&ref_count));

    if (atomic_dec_and_test(&ref_count)) {
        printk(KERN_ALERT "atomic_dec_and_test(ref_count) \n");
    }

    printk(KERN_ALERT "atomic_read(ref_count) = %d \n", atomic_read(&ref_count));

    //    if (atomic_dec_and_test(&ref_count)) {
    //         printk(KERN_ALERT "atomic_dec_and_test(ref_count) \n");
    //    }

    //    printk(KERN_ALERT "atomic_read(ref_count) = %d \n", atomic_read(&ref_count));

    if (atomic_inc_not_zero(&ref_count)){
        printk(KERN_ALERT "atomic_inc_not_zero(ref_count) \n");
    }

    printk(KERN_ALERT "atomic_read(ref_count) = %d \n", atomic_read(&ref_count));
    if (atomic_inc_not_zero(&ref_count)){
        printk(KERN_ALERT "atomic_inc_not_zero(ref_count) \n");
    }

    printk(KERN_ALERT "atomic_read(ref_count) = %d \n", atomic_read(&ref_count));

#endif


    /* COMPLETE */
#if 0
    init_completion(&comp);
    printk(KERN_ALERT "start complete \n");
    complete_write();
    complete_read();
    printk(KERN_ALERT "end complete \n");
#endif

    /* TASKLET */
#if 0
    float mydata = 10;
    float *pdata = &mydata;

    tasklet_init(&tasklet, tasklet_handle, (unsigned long)pdata);
    tasklet_schedule(&tasklet);
    tasklet_kill(&tasklet);

#endif

    /* LIST HEAD */
#if 1
    struct list_head todo_list, processing_list;
    INIT_LIST_HEAD(&todo_list);
    INIT_LIST_HEAD(&processing_list);

    list_item_t *list_item, *walk, *walk_next;
    list_item = walk = (list_item_t*)kmalloc(sizeof(list_item_t)*LIST_MAX_ITEM, GFP_KERNEL);
    if (list_item == NULL) {
        printk(KERN_ERR"Not enought memory\n");
        goto exit_program;
    }

    int i;
    for (i = 0; i< LIST_MAX_ITEM ; i++) {
        walk->data = i;
        list_add_tail(&walk->entry, &todo_list);
        walk++;
    }

    walk = list_first_entry(&todo_list, list_item_t , entry);
    printk(KERN_ALERT "first: %d \n", walk->data);

    list_for_each_entry_safe(walk, walk_next,&todo_list, entry) {
        list_move_tail(&walk->entry,&processing_list);
        printk(KERN_ALERT "todo item: %d \n", walk->data);
    }

    list_for_each_entry_safe(walk, walk_next,&processing_list, entry) {
        printk(KERN_ALERT "processing item: %d \n", walk->data);
    }


    if(likely(list_item)){
        kfree(list_item);
        printk(KERN_ALERT "kfree(list_item) \n");
    }


#endif


exit_program:
    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_ALERT "Ket thuc thanh cong\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NINHLD");
MODULE_VERSION("1.0.0");



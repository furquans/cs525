#include <xen/lib.h>

long do_test_vm(void)
{
  printk("Test VM hypercall");
  return(1);
}

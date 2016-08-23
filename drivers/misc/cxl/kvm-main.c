/*
 * Copyright 2016 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>


static int __init init_cxl_kvm(void)
{
  pr_info("Module loaded");
  return 0;
}


static void __exit exit_cxl_kvm(void)
{
  pr_info("Module unloaded");
}

module_init(init_cxl_kvm);
module_exit(exit_cxl_kvm);

MODULE_DESCRIPTION("IBM Coherent Accelerator");
MODULE_LICENSE("GPL");

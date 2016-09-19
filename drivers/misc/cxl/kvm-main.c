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
#include <linux/pci.h>


/* int cxl_pci_vphb_add(struct cxl_afu *afu) */
/* { */
/* 	struct pci_controller *phb; */
/* 	struct device_node *vphb_dn; */
/* 	struct device *parent; */

/* 	/\* */
/* 	 * If there are no AFU configuration records we won't have anything to */
/* 	 * expose under the vPHB, so skip creating one, returning success since */
/* 	 * this is still a valid case. This will also opt us out of EEH */
/* 	 * handling since we won't have anything special to do if there are no */
/* 	 * kernel drivers attached to the vPHB, and EEH handling is not yet */
/* 	 * supported in the peer model. */
/* 	 *\/ */
/* 	if (!afu->crs_num) */
/* 		return 0; */

/* 	/\* The parent device is the adapter. Reuse the device node of */
/* 	 * the adapter. */
/* 	 * We don't seem to care what device node is used for the vPHB, */
/* 	 * but tools such as lsvpd walk up the device parents looking */
/* 	 * for a valid location code, so we might as well show devices */
/* 	 * attached to the adapter as being located on that adapter. */
/* 	 *\/ */
/* 	parent = afu->adapter->dev.parent; */
/* 	vphb_dn = parent->of_node; */

/* 	/\* Alloc and setup PHB data structure *\/ */
/* 	phb = pcibios_alloc_controller(vphb_dn); */
/* 	if (!phb) */
/* 		return -ENODEV; */

/* 	/\* Setup parent in sysfs *\/ */
/* 	phb->parent = parent; */

/* 	/\* Setup the PHB using arch provided callback *\/ */
/* 	phb->ops = &cxl_pcie_pci_ops; */
/* 	phb->cfg_addr = NULL; */
/* 	phb->cfg_data = NULL; */
/* 	phb->private_data = afu; */
/* 	phb->controller_ops = cxl_pci_controller_ops; */

/* 	/\* Scan the bus *\/ */
/* 	pcibios_scan_phb(phb); */
/* 	if (phb->bus == NULL) */
/* 		return -ENXIO; */

/* 	/\* Claim resources. This might need some rework as well depending */
/* 	 * whether we are doing probe-only or not, like assigning unassigned */
/* 	 * resources etc... */
/* 	 *\/ */
/* 	pcibios_claim_one_bus(phb->bus); */

/* 	/\* Add probed PCI devices to the device model *\/ */
/* 	pci_bus_add_devices(phb->bus); */

/* 	afu->phb = phb; */

/* 	return 0; */
/* } */

static struct pci_dev *dev_cxl;


static int walk_bus(struct pci_dev *dev, void *data)
{
	if (dev->vendor == PCI_VENDOR_ID_IBM &&  dev->class==0x120000) {
		pr_info("%p\n",dev);
		dev_cxl = 
		return 1;
	}
	return 0;
}

static int __init init_cxl_kvm(void)
{

	struct pci_dev cxl_dev = pci_get_device(PCI_VENDOR_ID_IBM, 0x4350);


		pr_info("%p\n",dev);
	
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

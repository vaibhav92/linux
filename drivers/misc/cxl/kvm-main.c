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
#include <asm/bug.h>


static struct pci_dev *cxl_dev;

static int cxl_dma_set_mask(struct pci_dev *pdev, u64 dma_mask)
{

		pr_info("Tag %s:%d\n", __FILE__, __LINE__);

	if (dma_mask < DMA_BIT_MASK(64)) {
		pr_info("%s only 64bit DMA supported on CXL", __func__);
		return -EIO;
	}

	*(pdev->dev.dma_mask) = dma_mask;
	return 0;
}

static int cxl_pci_probe_mode(struct pci_bus *bus)
{
		pr_info("Tag %s:%d\n", __FILE__, __LINE__);

	return PCI_PROBE_NORMAL;
}

static int cxl_setup_msi_irqs(struct pci_dev *pdev, int nvec, int type)
{
		pr_info("Tag %s:%d\n", __FILE__, __LINE__);

	return -ENODEV;
}

static void cxl_teardown_msi_irqs(struct pci_dev *pdev)
{
		pr_info("Tag %s:%d\n", __FILE__, __LINE__);

	/*
	 * MSI should never be set but need still need to provide this call
	 * back.
	 */
}

static bool cxl_pci_enable_device_hook(struct pci_dev *dev)
{
		pr_info("Tag %s:%d\n", __FILE__, __LINE__);

	/* struct pci_controller *phb; */
	/* struct cxl_afu *afu; */

	/* phb = pci_bus_to_host(dev->bus); */
	/* afu = (struct cxl_afu *)phb->private_data; */

	/* if (!cxl_ops->link_ok(afu->adapter, afu)) { */
	/* 	dev_warn(&dev->dev, "%s: Device link is down, refusing to enable AFU\n", __func__); */
	/* 	return false; */
	/* } */

	set_dma_ops(&dev->dev, &dma_direct_ops);
	set_dma_offset(&dev->dev, PAGE_OFFSET);

	return 0;
}

static resource_size_t cxl_pci_window_alignment(struct pci_bus *bus,
						unsigned long type)
{
	pr_info("Tag %s:%d\n", __FILE__, __LINE__);

	return 1;
}

static void cxl_pci_reset_secondary_bus(struct pci_dev *dev)
{
	/* Should we do an AFU reset here ? */
	pr_info("Tag %s:%d\n", __FILE__, __LINE__);

}

/* static int cxl_pcie_cfg_record(u8 bus, u8 devfn) */
/* { */
/* 	return (bus << 8) + devfn; */
/* } */

/* static int cxl_pcie_config_info(struct pci_bus *bus, unsigned int devfn, */
/* 				struct cxl_afu **_afu, int *_record) */
/* { */
/* 	struct pci_controller *phb; */
/* 	struct cxl_afu *afu; */
/* 	int record; */

/* 	phb = pci_bus_to_host(bus); */
/* 	if (phb == NULL) */
/* 		return PCIBIOS_DEVICE_NOT_FOUND; */

/* 	afu = (struct cxl_afu *)phb->private_data; */
/* 	record = cxl_pcie_cfg_record(bus->number, devfn); */
/* 	if (record > afu->crs_num) */
/* 		return PCIBIOS_DEVICE_NOT_FOUND; */

/* 	*_afu = afu; */
/* 	*_record = record; */
/* 	return 0; */
/* } */

static int cxl_pcie_read_config(struct pci_bus *bus, unsigned int devfn,
				int offset, int len, u32 *val)
{
	//pr_info("Tag %s, %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
	pr_info("%s, Devfn=%d offset=%d len=%d \n", __FUNCTION__, devfn, offset, len);
	
	if (devfn)
		return PCIBIOS_FUNC_NOT_SUPPORTED;
	
	return pci_generic_config_read(cxl_dev->bus, cxl_dev->devfn, offset, len, val);

	
	/* int rc, record; */
	/* struct cxl_afu *afu; */
	/* u8 val8; */
	/* u16 val16; */
	/* u32 val32; */

	/* rc = cxl_pcie_config_info(bus, devfn, &afu, &record); */
	/* if (rc) */
	/* 	return rc; */

	/* switch (len) { */
	/* case 1: */
	/* 	rc = cxl_ops->afu_cr_read8(afu, record, offset,	&val8); */
	/* 	*val = val8; */
	/* 	break; */
	/* case 2: */
	/* 	rc = cxl_ops->afu_cr_read16(afu, record, offset, &val16); */
	/* 	*val = val16; */
	/* 	break; */
	/* case 4: */
	/* 	rc = cxl_ops->afu_cr_read32(afu, record, offset, &val32); */
	/* 	*val = val32; */
	/* 	break; */
	/* default: */
	/* 	WARN_ON(1); */
	/* } */

	/* if (rc) */
	/* 	return PCIBIOS_DEVICE_NOT_FOUND; */

	return PCIBIOS_DEVICE_NOT_FOUND;
}

static int cxl_pcie_write_config(struct pci_bus *bus, unsigned int devfn,
				 int offset, int len, u32 val)
{
	pr_info("%s, Devfn=%d offset=%d len=%d \n", __FUNCTION__, devfn, offset, len);
	
	if (devfn)
		return PCIBIOS_FUNC_NOT_SUPPORTED;
	
	return pci_generic_config_write(cxl_dev->bus, cxl_dev->devfn, offset, len, val);
		

	/* int rc, record; */
	/* struct cxl_afu *afu; */

	/* rc = cxl_pcie_config_info(bus, devfn, &afu, &record); */
	/* if (rc) */
	/* 	return rc; */

	/* switch (len) { */
	/* case 1: */
	/* 	rc = cxl_ops->afu_cr_write8(afu, record, offset, val & 0xff); */
	/* 	break; */
	/* case 2: */
	/* 	rc = cxl_ops->afu_cr_write16(afu, record, offset, val & 0xffff); */
	/* 	break; */
	/* case 4: */
	/* 	rc = cxl_ops->afu_cr_write32(afu, record, offset, val); */
	/* 	break; */
	/* default: */
	/* 	WARN_ON(1); */
	/* } */

	/* if (rc) */
		/* return PCIBIOS_SET_FAILED; */

	/* return PCIBIOS_SUCCESSFUL; */
}

static struct pci_ops cxl_pcie_pci_ops =
{
	.read = cxl_pcie_read_config,
	.write = cxl_pcie_write_config,
};


static struct pci_controller_ops cxl_pci_controller_ops =
{
	.probe_mode = cxl_pci_probe_mode,
	.enable_device_hook = cxl_pci_enable_device_hook,
	/* .disable_device = _cxl_pci_disable_device, */
	/* .release_device = _cxl_pci_disable_device, */
	.window_alignment = cxl_pci_window_alignment,
	.reset_secondary_bus = cxl_pci_reset_secondary_bus,
	.setup_msi_irqs = cxl_setup_msi_irqs,
	.teardown_msi_irqs = cxl_teardown_msi_irqs,
	.dma_set_mask = cxl_dma_set_mask,
};



static int __init init_cxl_kvm(void)
{
	struct device * parent;
	struct pci_controller *phb;
	struct device_node *vphb_dn;


	/* creating kvm vphb bus only supported on bare-metal */
	if (!cpu_has_feature(CPU_FTR_HVMODE)) {
		dev_info(&cxl_dev->dev,"VFIO vphb bus only supported on bare metal");
		return -ENODEV;
	}

	/* Right noow find a capi card for out work.*/
	/* TODO: Ultimatly need to walk to pci bus to find all the capi devices */
	//	cxl_dev = pci_get_device(PCI_VENDOR_ID_IBM, 0x4350, NULL);
	cxl_dev = pci_get_device(PCI_VENDOR_ID_IBM, 0x477, NULL);

	if (!cxl_dev) {
		pr_err("No suitable cxl device found\n");
		return -ENODEV;
	}

	pr_info("%p\n",cxl_dev);

	parent = cxl_dev->dev.parent;
	vphb_dn = parent->of_node;

	/* Alloc and setup PHB data structure */
	phb = pcibios_alloc_controller(vphb_dn);
	if (!phb)
		return -ENODEV;

	/* Setup parent in sysfs */
	phb->parent = parent;

	/* Setup the PHB using arch provided callback */
	phb->ops = &cxl_pcie_pci_ops;
	phb->cfg_addr = NULL;
	phb->cfg_data = NULL;
	phb->private_data = NULL;
	phb->controller_ops = cxl_pci_controller_ops;

	/* Scan the bus */
	pcibios_scan_phb(phb);
	if (phb->bus == NULL)
		return -ENXIO;

	/* Claim resources. This might need some rework as well depending
	 * whether we are doing probe-only or not, like assigning unassigned
	 * resources etc...
	 */
	pcibios_claim_one_bus(phb->bus);

	/* Add probed PCI devices to the device model */
	pci_bus_add_devices(phb->bus);

	pci_dev_put(cxl_dev);
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

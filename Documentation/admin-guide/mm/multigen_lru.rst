.. SPDX-License-Identifier: GPL-2.0

=====================
Multigenerational LRU
=====================

Quick start
===========
Build configurations
--------------------
:Required: Set ``CONFIG_LRU_GEN=y``.

:Optional: Set ``CONFIG_LRU_GEN_ENABLED=y`` to enable the
 multigenerational LRU by default.

Runtime configurations
----------------------
:Required: Write ``y`` to ``/sys/kernel/mm/lru_gen/enable`` if
 ``CONFIG_LRU_GEN_ENABLED=n``.

This file accepts different values to enabled or disabled the
following features:

====== ========
Values Features
====== ========
0x0001 the multigenerational LRU
0x0002 clear the accessed bit in leaf page table entries **in large
       batches**, when MMU sets it (e.g., on x86)
0x0004 clear the accessed bit in non-leaf page table entries **as
       well**, when MMU sets it (e.g., on x86)
[yYnN] apply to all the features above
====== ========

E.g.,
::

    echo y >/sys/kernel/mm/lru_gen/enabled
    cat /sys/kernel/mm/lru_gen/enabled
    0x0007
    echo 5 >/sys/kernel/mm/lru_gen/enabled
    cat /sys/kernel/mm/lru_gen/enabled
    0x0005

Most users should enable or disable all the features unless some of
them have unforeseen side effects.

Recipes
=======
Personal computers
------------------
Personal computers are more sensitive to thrashing because it can
cause janks (lags when rendering UI) and negatively impact user
experience. The multigenerational LRU offers thrashing prevention to
the majority of laptop and desktop users who don't have oomd.

:Thrashing prevention: Write ``N`` to
 ``/sys/kernel/mm/lru_gen/min_ttl_ms`` to prevent the working set of
 ``N`` milliseconds from getting evicted. The OOM killer is triggered
 if this working set can't be kept in memory. Based on the average
 human detectable lag (~100ms), ``N=1000`` usually eliminates
 intolerable janks due to thrashing. Larger values like ``N=3000``
 make janks less noticeable at the risk of premature OOM kills.

Data centers
------------
Data centers want to optimize job scheduling (bin packing) to improve
memory utilizations. Job schedulers need to estimate whether a server
can allocate a certain amount of memory for a new job, and this step
is known as working set estimation, which doesn't impact the existing
jobs running on this server. They also want to attempt freeing some
cold memory from the existing jobs, and this step is known as proactive
reclaim, which improves the chance of landing a new job successfully.

:Optional: Increase ``CONFIG_NR_LRU_GENS`` to support more generations
 for working set estimation and proactive reclaim.

:Debugfs interface: ``/sys/kernel/debug/lru_gen`` has the following
 format:
 ::

   memcg  memcg_id  memcg_path
     node  node_id
       min_gen  birth_time  anon_size  file_size
       ...
       max_gen  birth_time  anon_size  file_size

 ``min_gen`` is the oldest generation number and ``max_gen`` is the
 youngest generation number. ``birth_time`` is in milliseconds.
 ``anon_size`` and ``file_size`` are in pages. The youngest generation
 represents the group of the MRU pages and the oldest generation
 represents the group of the LRU pages. For working set estimation, a
 job scheduler writes to this file at a certain time interval to
 create new generations, and it ranks available servers based on the
 sizes of their cold memory defined by this time interval. For
 proactive reclaim, a job scheduler writes to this file before it
 tries to land a new job, and if it fails to materialize the cold
 memory without impacting the existing jobs, it retries on the next
 server according to the ranking result.

 This file accepts commands in the following subsections. Multiple
 command lines are supported, so does concatenation with delimiters
 ``,`` and ``;``.

 ``/sys/kernel/debug/lru_gen_full`` contains additional stats for
 debugging.

:Working set estimation: Write ``+ memcg_id node_id max_gen
 [can_swap [full_scan]]`` to ``/sys/kernel/debug/lru_gen`` to invoke
 the aging. It scans PTEs for hot pages and promotes them to the
 youngest generation ``max_gen``. Then it creates a new generation
 ``max_gen+1``. Set ``can_swap`` to ``1`` to scan for hot anon pages
 when swap is off. Set ``full_scan`` to ``0`` to reduce the overhead
 as well as the coverage when scanning PTEs.

:Proactive reclaim: Write ``- memcg_id node_id min_gen [swappiness
 [nr_to_reclaim]]`` to ``/sys/kernel/debug/lru_gen`` to invoke the
 eviction. It evicts generations less than or equal to ``min_gen``.
 ``min_gen`` should be less than ``max_gen-1`` as ``max_gen`` and
 ``max_gen-1`` aren't fully aged and therefore can't be evicted. Use
 ``nr_to_reclaim`` to limit the number of pages to evict.

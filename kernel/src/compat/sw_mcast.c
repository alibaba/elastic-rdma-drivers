// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include "sw.h"
#include "sw_loc.h"

void sw_drop_all_mcast_groups(struct sw_qp *qp)
{
	struct sw_mc_grp *grp;
	struct sw_mc_elem *elem;

	while (1) {
		spin_lock_bh(&qp->grp_lock);
		if (list_empty(&qp->grp_list)) {
			spin_unlock_bh(&qp->grp_lock);
			break;
		}
		elem = list_first_entry(&qp->grp_list, struct sw_mc_elem,
					grp_list);
		list_del(&elem->grp_list);
		spin_unlock_bh(&qp->grp_lock);

		grp = elem->grp;
		spin_lock_bh(&grp->mcg_lock);
		list_del(&elem->qp_list);
		grp->num_qp--;
		spin_unlock_bh(&grp->mcg_lock);
		sw_drop_ref(grp);
		sw_drop_ref(elem);
	}
}

void sw_mc_cleanup(struct sw_pool_entry *arg)
{
	struct sw_mc_grp *grp = container_of(arg, typeof(*grp), pelem);
	struct sw_dev *sw = grp->sw;

	sw_drop_key(grp);
	sw_mcast_delete(sw, &grp->mgid);
}

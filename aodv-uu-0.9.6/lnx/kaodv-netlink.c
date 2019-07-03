/*****************************************************************************
 *
 * Copyright (C) 2001 Uppsala University and Ericsson AB.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Erik Nordström, <erik.nordstrom@it.uu.se>
 *
 *****************************************************************************/
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
#include <linux/config.h>
#endif
#include <linux/if.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <linux/version.h>
#include <linux/semaphore.h>

#include <linux/net.h>							

#ifdef KERNEL26
#include <linux/security.h>
#endif
#include <net/sock.h>

#include "kaodv-netlink.h"
#include "kaodv-expl.h"
#include "kaodv-queue.h"
#include "kaodv-debug.h"
#include "kaodv.h"

static int peer_pid;
static struct sock *kaodvnl;
//#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36))
//static DECLARE_MUTEX(kaodvnl_sem);
//#else
static DEFINE_SEMAPHORE(kaodvnl_sem);
//#endif

/* For 2.4 backwards compatibility */
#ifndef KERNEL26
#define sk_receive_queue receive_queue
#define sk_socket socket
#endif



extern int active_route_timeout, qual_th, is_gateway;

static struct sk_buff *kaodv_netlink_build_msg(int type, void *data, int len)
{
    /*printk(KERN_ALERT "netlink_build\n");*/
    unsigned char *old_tail;
    size_t size = 0;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    void *m;

    size = NLMSG_SPACE(len);

    skb = alloc_skb(size, GFP_ATOMIC);

    if (!skb)
        goto nlmsg_failure;

    old_tail = SKB_TAIL_PTR(skb);
//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,17))
    nlh = nlmsg_put(skb, 0, 0, type, size - sizeof(*nlh),0);
//#else
//    nlh = NLMSG_PUT(skb, 0, 0, type, size - sizeof(*nlh));
//#endif

    m = NLMSG_DATA(nlh);

    memcpy(m, data, len);

    nlh->nlmsg_len = SKB_TAIL_PTR(skb) - old_tail;


//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,17))
    NETLINK_CB(skb).portid = 0;  /* from kernel */
//#else
 //   NETLINK_CB(skb).pid = 0;  /* from kernel */
//#endif

    return skb;

nlmsg_failure:
    if (skb)
        kfree_skb(skb);

    printk(KERN_ERR "kaodv: error creating rt timeout message\n");

    return NULL;
}

void kaodv_netlink_send_debug_msg(char *buf, int len)
{
    /*printk(KERN_ALERT "kaodv_netlink_send_debug_msg\n");*/
    struct sk_buff *skb = NULL;

    skb = kaodv_netlink_build_msg(KAODVM_DEBUG, buf, len);

    if (skb == NULL) {
        printk("kaodv_netlink: skb=NULL\n");
        return;
    }

    netlink_broadcast(kaodvnl, skb, peer_pid, AODVGRP_NOTIFY, GFP_USER);
}

void kaodv_netlink_send_rt_msg(int type, __u32 src, __u32 dest)
{
    /*printk(KERN_ALERT "kaodv_netlink_send_rt_msg\n");*/
    struct sk_buff *skb = NULL;
    struct kaodv_rt_msg m;

    memset(&m, 0, sizeof(m));

    m.src = src;
    m.dst = dest;

    skb = kaodv_netlink_build_msg(type, &m, sizeof(struct kaodv_rt_msg));

    if (skb == NULL) {
        printk("kaodv_netlink: skb=NULL\n");
        return;
    }

    /* 	netlink_unicast(kaodvnl, skb, peer_pid, MSG_DONTWAIT); */
    netlink_broadcast(kaodvnl, skb, 0, AODVGRP_NOTIFY, GFP_USER);
}

void kaodv_netlink_send_rt_update_msg(int type, __u32 src, __u32 dest,
        int ifindex)
{
    /*printk(KERN_ALERT "kaodv_netlink_send_rt_update_msg\n");*/
    struct sk_buff *skb = NULL;
    struct kaodv_rt_msg m;

    memset(&m, 0, sizeof(m));

    m.type = type;
    m.src = src;
    m.dst = dest;
    m.ifindex = ifindex;

    skb = kaodv_netlink_build_msg(KAODVM_ROUTE_UPDATE, &m,
            sizeof(struct kaodv_rt_msg));

    if (skb == NULL) {
        printk("kaodv_netlink: skb=NULL\n");
        return;
    }
    /* netlink_unicast(kaodvnl, skb, peer_pid, MSG_DONTWAIT); */
    netlink_broadcast(kaodvnl, skb, 0, AODVGRP_NOTIFY, GFP_USER);
}

void kaodv_netlink_send_rerr_msg(int type, __u32 src, __u32 dest, int ifindex)
{
    /*printk(KERN_ALERT "kaodv_netlink_send_rerr_msg\n");*/
    struct sk_buff *skb = NULL;
    struct kaodv_rt_msg m;

    memset(&m, 0, sizeof(m));

    m.type = type;
    m.src = src;
    m.dst = dest;
    m.ifindex = ifindex;

    skb = kaodv_netlink_build_msg(KAODVM_SEND_RERR, &m,
            sizeof(struct kaodv_rt_msg));

    if (skb == NULL) {
        printk("kaodv_netlink: skb=NULL\n");
        return;
    }
    /* netlink_unicast(kaodvnl, skb, peer_pid, MSG_DONTWAIT); */
    netlink_broadcast(kaodvnl, skb, 0, AODVGRP_NOTIFY, GFP_USER);
}

static int kaodv_netlink_receive_peer(unsigned char type, void *msg,
        unsigned int len)
{
    /*printk(KERN_ALERT "kaodv_netlink_receive_peer\n");*/
    int ret = 0;
    struct kaodv_rt_msg *m;
    struct kaodv_conf_msg *cm;
    struct expl_entry e;

    KAODV_DEBUG("Received msg: %s", kaodv_msg_type_to_str(type));

    switch (type) {
        case KAODVM_ADDROUTE:
            if (len < sizeof(struct kaodv_rt_msg))
                return -EINVAL;

            m = (struct kaodv_rt_msg *)msg;

            ret = kaodv_expl_get(m->dst, &e);

            if (ret < 0) {
                ret = kaodv_expl_update(m->dst, m->nhop, m->time,
                        m->flags, m->ifindex);
            } else {
                ret = kaodv_expl_add(m->dst, m->nhop, m->time,
                        m->flags, m->ifindex);
            }
            kaodv_queue_set_verdict(KAODV_QUEUE_SEND, m->dst);
            break;
        case KAODVM_DELROUTE:
            if (len < sizeof(struct kaodv_rt_msg))
                return -EINVAL;

            m = (struct kaodv_rt_msg *)msg;
            kaodv_expl_del(m->dst);
            kaodv_queue_set_verdict(KAODV_QUEUE_DROP, m->dst);
            break;
        case KAODVM_NOROUTE_FOUND:
            if (len < sizeof(struct kaodv_rt_msg))
                return -EINVAL;

            m = (struct kaodv_rt_msg *)msg;
            KAODV_DEBUG("No route found for %s", print_ip(m->dst));
            kaodv_queue_set_verdict(KAODV_QUEUE_DROP, m->dst);
            break;
        case KAODVM_CONFIG:
            if (len < sizeof(struct kaodv_conf_msg))
                return -EINVAL;

            cm = (struct kaodv_conf_msg *)msg;
            active_route_timeout = cm->active_route_timeout;
            qual_th = cm->qual_th;
            is_gateway = cm->is_gateway;
            break;
        default:
            printk("kaodv-netlink: Unknown message type\n");
            ret = -EINVAL;
    }
    return ret;
}

static int kaodv_netlink_rcv_nl_event(struct notifier_block *this,
        unsigned long event, void *ptr)
{
    /*printk(KERN_ALERT "kaodv_netlink_rcv_nl_event\n");*/
    struct netlink_notify *n = ptr;


//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,17))
    if (event == NETLINK_URELEASE && n->protocol == NETLINK_AODV && n->portid) {
        if (n->portid == peer_pid) {
//#else
 //  if (event == NETLINK_URELEASE && n->protocol == NETLINK_AODV && n->pid) {
 //       if (n->pid == peer_pid) {
//#endif
            peer_pid = 0;
            kaodv_expl_flush();
            kaodv_queue_flush();
        }
        return NOTIFY_DONE;
    }

    return NOTIFY_DONE;
}

static struct notifier_block kaodv_nl_notifier = {
    .notifier_call = kaodv_netlink_rcv_nl_event,
};

#define RCV_SKB_FAIL(err) do { netlink_ack(skb, nlh, (err),NULL);printk(KERN_ALERT "err ack for the request!!!"); return; } while (0)

static inline void kaodv_netlink_rcv_skb(struct sk_buff *skb)
{
    /*printk(KERN_ALERT "get in the function kaodv_netlink_rcv_skb()");*/
    int status, type, pid, flags, nlmsglen, skblen;
    struct nlmsghdr *nlh;

    skblen = skb->len;
    if (skblen < sizeof(struct nlmsghdr)) {
        printk("skblen to small\n");
        return;
    }

    nlh = (struct nlmsghdr *)skb->data;
    nlmsglen = nlh->nlmsg_len;

    if (nlmsglen < sizeof(struct nlmsghdr) || skblen < nlmsglen) {
        printk("nlsmsg=%d skblen=%d to small\n", nlmsglen, skblen);
        return;
    }

    printk(KERN_ALERT "debug test the kernel!!!\n");

    pid = nlh->nlmsg_pid;
    flags = nlh->nlmsg_flags;

    if (pid <= 0 || !(flags & NLM_F_REQUEST) || flags & NLM_F_MULTI)
    {
        printk(KERN_ALERT "pid or flags is error\n");
        RCV_SKB_FAIL(-EINVAL);
    }


    if (flags & MSG_TRUNC)
    {
        printk(KERN_ALERT "pid or flags is error\n");
        RCV_SKB_FAIL(-ECOMM);
    }

    type = nlh->nlmsg_type;


    printk(KERN_ALERT "debug test the kernel!!!aaaaaaa\n");
    printk("kaodv_netlink: type=%d\n", type);
    /* if (type < NLMSG_NOOP || type >= IPQM_MAX) */
    /* 		RCV_SKB_FAIL(-EINVAL); */
#ifdef KERNEL26

    printk(KERN_ALERT "kernel version is %d\n",LINUX_VERSION_CODE);
#if 0
    if(capable(CAP_NET_ADMIN))
    {
        RCV_SKB_FAIL(-EPERM);
    }
    if (cap_raised(current_cap(),CAP_NET_ADMIN))
    {
        printk(KERN_ALERT "kernel netlink error\n");
        RCV_SKB_FAIL(-EPERM);
    }
#endif

#endif
//#endif
    //write_lock_bh(&queue_lock);

    if (peer_pid) {
        if (peer_pid != pid) {
            //write_unlock_bh(&queue_lock);
            RCV_SKB_FAIL(-EBUSY);
        }
    } else
        peer_pid = pid;

    //write_unlock_bh(&queue_lock);

    status = kaodv_netlink_receive_peer(type, NLMSG_DATA(nlh),
            skblen - NLMSG_LENGTH(0));
    if (status < 0)
        RCV_SKB_FAIL(status);

    if (flags & NLM_F_ACK)
    {
        printk(KERN_ALERT"kernel send the msg!!!!!!\n");
        netlink_ack(skb, nlh, 0,NULL);
    }
    else
    {
        printk(KERN_ALERT "kernel send the err mesg!!!!!\n");
    }
    return;
}

#if 0
static void kaodv_netlink_rcv_sk(struct sock *sk, int len)
{
    do {
        struct sk_buff *skb;

        if (down_trylock(&kaodvnl_sem))
            return;

        while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
            kaodv_netlink_rcv_skb(skb);
            kfree_skb(skb);
        }

        up(&kaodvnl_sem);

    } while (kaodvnl && kaodvnl->sk_receive_queue.qlen);

    return;
}
#endif

//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,17))

//#endif

int kaodv_netlink_init(void)
{struct netlink_kernel_cfg cfg = {
	.groups=AODVGRP_MAX,
    .input = kaodv_netlink_rcv_skb,
};
    /*printk(KERN_ALERT "kaodv_netlink_init and the LINUX_VERSION_CODE is %d\n",LINUX_VERSION_CODE);*/
    netlink_register_notifier(&kaodv_nl_notifier);
//#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
  //  printk(KERN_ALERT "kaodv_netlink_init and the LINUX_VERSION_CODE is small than 2.6.14");
    //kaodvnl = netlink_kernel_create(NETLINK_AODV, kaodv_netlink_rcv_sk);
//#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
  //  printk(KERN_ALERT "kaodv_netlink_init and the LINUX_VERSION_CODE is small than 2.6.22");
    //kaodvnl = netlink_kernel_create(NETLINK_AODV, AODVGRP_MAX, kaodv_netlink_rcv_sk, THIS_MODULE);
//#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
  //  printk(KERN_ALERT "kaodv_netlink_init and the LINUX_VERSION_CODE is small than 2.6.24");
    //kaodvnl = netlink_kernel_create(NETLINK_AODV, AODVGRP_MAX, kaodv_netlink_rcv_sk, NULL, THIS_MODULE);
//#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,12,17))
  //  kaodvnl = netlink_kernel_create(&init_net, NETLINK_AODV, AODVGRP_MAX,
    // kaodv_netlink_rcv_skb, NULL, THIS_MODULE);
//#else
    kaodvnl = netlink_kernel_create(&init_net, NETLINK_AODV,&cfg);

    printk(KERN_ALERT "kaodv_netlink_init and the LINUX_VERSION_CODE is high than 2.6.24");
//#endif

    if (kaodvnl == NULL) {
        printk(KERN_ERR "kaodv_netlink: failed to create netlink socket\n");
        netlink_unregister_notifier(&kaodv_nl_notifier);
        return -1;
    }
    return 0;
}

void kaodv_netlink_fini(void)
{
    printk(KERN_ALERT "kaodv_netlink_fini\n");
    sock_release(kaodvnl->sk_socket);
    down(&kaodvnl_sem);
    up(&kaodvnl_sem);

    netlink_unregister_notifier(&kaodv_nl_notifier);
}

/*
 * parpd: ARP BPF filter
 * Copyright (c) 2006-2017 Roy Marples <roy@marples.name>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef BPF_WHOLEPACKET
# define BPF_WHOLEPACKET ~0U
#endif

/* This is hardcoded for ethernet. */
static const struct bpf_insn bpf_arp_filter [] = {
	/* Ensure packet is at least correct size. */
	BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),
	BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(struct ether_arp), 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Check this is an ARP packet. */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	         offsetof(struct ether_header, ether_type)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Load frame header length into X */
	BPF_STMT(BPF_LDX + BPF_W + BPF_IMM, sizeof(struct ether_header)),

	/* Make sure the hardware family matches. */
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, offsetof(struct arphdr, ar_hrd)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPHRD_ETHER, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Make sure the hardware length matches. */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(struct arphdr, ar_hln)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	         sizeof((struct ether_arp *)0)->arp_sha, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Make sure this is for IP. */
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, offsetof(struct arphdr, ar_pro)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* Make sure this is an ARP REQUEST. */
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, offsetof(struct arphdr, ar_op)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 2, 0),

	/* Make sure the protocol length matches. */
	BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(struct arphdr, ar_pln)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, sizeof(in_addr_t), 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),

	/* If we passed all the tests, ask for the whole packet. */
	BPF_STMT(BPF_RET + BPF_K, BPF_WHOLEPACKET),
};
#define bpf_arp_filter_len sizeof(bpf_arp_filter) / sizeof(bpf_arp_filter[0])

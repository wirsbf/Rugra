/*
 * Minimal x86-64 ELF input for the locked Ghidra 12.0.4 Program metadata
 * producer fixture.  It deliberately has no libc or dynamic-loader state.
 *
 * tail_user has a non-entry direct jump to shared_ret.  cond_user has a
 * conditional jump to the same function entry.  exit really returns so that
 * only the name-driven Known No-Return analyzer marks it non-returning.
 */

	.section .text
	.balign 16, 0x90
	.globl _start
	.type _start, @function
_start:
	xorl %edi, %edi
	call tail_user
	call cond_user
	call noreturn_caller
	hlt
	.size _start, .-_start

	.balign 16, 0x90
	.globl shared_ret
	.type shared_ret, @function
shared_ret:
	movl $7, %eax
	ret
	.size shared_ret, .-shared_ret

	.balign 16, 0x90
	.globl tail_user
	.type tail_user, @function
tail_user:
	testl %edi, %edi
	jne tail_local_return
	nop
	.globl tail_jump_site
	.type tail_jump_site, @notype
tail_jump_site:
	jmp shared_ret
tail_local_return:
	xorl %eax, %eax
	ret
	.size tail_user, .-tail_user

	.balign 16, 0x90
	.globl cond_user
	.type cond_user, @function
cond_user:
	testl %edi, %edi
	.globl cond_jump_site
	.type cond_jump_site, @notype
cond_jump_site:
	je shared_ret
	movl $1, %eax
	ret
	.size cond_user, .-cond_user

	.balign 16, 0x90
	.globl exit
	.type exit, @function
exit:
	ret
	.size exit, .-exit

	.balign 16, 0x90
	.globl noreturn_caller
	.type noreturn_caller, @function
noreturn_caller:
	.globl exit_call_site
	.type exit_call_site, @notype
exit_call_site:
	call exit
	.globl after_exit_site
	.type after_exit_site, @notype
after_exit_site:
	movl $0x11223344, %eax
	ret
	.size noreturn_caller, .-noreturn_caller

	.section .note.GNU-stack,"",@progbits

	.text
	.def	@feat.00;
	.scl	3;
	.type	0;
	.endef
	.globl	@feat.00
.set @feat.00, 0
	.file	"llvm-link"
                                        # Start of file scope inline assembly
	.globl	_ZSt21ios_base_library_initv
	.globl	_ZSt21ios_base_library_initv

                                        # End of file scope inline assembly
	.def	_Z15exampleFunctionv;
	.scl	2;
	.type	32;
	.endef
	.globl	_Z15exampleFunctionv            # -- Begin function _Z15exampleFunctionv
	.p2align	4, 0x90
_Z15exampleFunctionv:                   # @_Z15exampleFunctionv
.seh_proc _Z15exampleFunctionv
# %bb.0:
	subq	$40, %rsp
	.seh_stackalloc 40
	.seh_endprologue
	movq	.refptr._ZSt4cout(%rip), %rcx
	leaq	.L.str(%rip), %rdx
	callq	_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
	leaq	_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_(%rip), %rdx
	movq	%rax, %rcx
	callq	_ZNSolsEPFRSoS_E
	nop
	addq	$40, %rsp
	retq
	.seh_endproc
                                        # -- End function
	.def	main;
	.scl	2;
	.type	32;
	.endef
	.globl	main                            # -- Begin function main
	.p2align	4, 0x90
main:                                   # @main
.seh_proc main
# %bb.0:
	pushq	%rbp
	.seh_pushreg %rbp
	subq	$128, %rsp
	.seh_stackalloc 128
	leaq	128(%rsp), %rbp
	.seh_setframe %rbp, 128
	.seh_endprologue
	callq	__main
	movl	$0, -4(%rbp)
	movq	.refptr._ZSt4cout(%rip), %rcx
	leaq	.L.str.1(%rip), %rdx
	callq	_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
	leaq	_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_(%rip), %rdx
	movq	%rax, %rcx
	callq	_ZNSolsEPFRSoS_E
	movl	$42, -12(%rbp)
	movl	-12(%rbp), %eax
	shll	$1, %eax
	movl	%eax, -8(%rbp)
	imull	$69, -8(%rbp), %eax
	movl	%eax, -36(%rbp)
	callq	_Z15exampleFunctionv
	leaq	.L.str.1.2(%rip), %rcx
	callq	*__imp_LoadLibraryA(%rip)
	movq	%rax, -24(%rbp)
	cmpq	$0, %rax
	jne	.LBB1_2
# %bb.1:
	movl	$-1, -4(%rbp)
	jmp	.LBB1_3
.LBB1_2:
	movq	-24(%rbp), %rcx
	leaq	.L.str.2(%rip), %rdx
	callq	*__imp_GetProcAddress(%rip)
	movq	%rax, -32(%rbp)
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	xorl	%r8d, %r8d
	xorl	%r9d, %r9d
	movl	$0, 32(%rsp)
	movq	$0, 40(%rsp)
	movq	$0, 48(%rsp)
	movl	$0, 56(%rsp)
	movl	$0, 64(%rsp)
	movl	$0, 72(%rsp)
	callq	*-32(%rbp)
	movl	$0, -4(%rbp)
.LBB1_3:
	movl	-4(%rbp), %eax
	addq	$128, %rsp
	popq	%rbp
	retq
	.seh_endproc
                                        # -- End function
	.section	.rdata,"dr"
.L.str:                                 # @.str
	.asciz	"Yippie from Subfunction."

.L.str.1:                               # @.str.1
	.asciz	"Hello, World!"

.L.str.1.2:                             # @.str.1.2
	.asciz	"ntdll"

.L.str.2:                               # @.str.2
	.asciz	"NtMapViewOfSection"

	.section	.rdata$.refptr._ZSt4cout,"dr",discard,.refptr._ZSt4cout
	.p2align	3, 0x0
	.globl	.refptr._ZSt4cout
.refptr._ZSt4cout:
	.quad	_ZSt4cout
	.addrsig
	.addrsig_sym _ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
	.addrsig_sym _ZSt4cout

.global mpk_trampoline
.type mpk_trampoline,@function
mpk_trampoline:
# Save rdx and rcx as they contain arguments
    push %rdx
    push %rcx
    mov    $0x0,%eax
    mov    $0x0,%ecx
    mov    $0x0,%edx
    wrpkru

# Restore rdx and rcx
    pop %rcx
    pop %rdx
# We don't need jump target anymore
# Get slot number
    pop %rax
    push %rbx
    mov gotplt_address@GOTPCREL(%rip), %rbx
#index into gotplt_address array to call target func
    mov (%rbx,%rax,8),%rax
    xor %rbx, %rbx
    callq *%rax
#Store rax into rbx before wrpkru
    mov %rax, %rbx
    mov    $0x10,%eax
    mov    $0x0,%ecx
    mov    $0x0,%edx
    wrpkru
# Restore rax
    mov %rbx, %rax
    pop %rbx

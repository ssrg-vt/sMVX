.global mpk_trampoline
.type mpk_trampoline,@function
mpk_trampoline:
# Save rdx and rcx as they contain arguments, old rax already saved
    push %rdx
    push %rcx
    mov    $0x0,%eax
    mov    $0x0,%ecx
    mov    $0x0,%edx
    wrpkru

# Restore rdx and rcx
    pop %rcx
    pop %rdx

# At this point, the stack looks like this:
  #########
  # slot  #
  #########
  # %rax  #
  #########
  # %rbx  #
  #########

# Setup safestack and store unsafestack
    #int3
# Dereference unsafe stack address and store unsafestack pointer
    mov unsafestack@GOTPCREL(%rip), %rax
    mov %rsp, (%rax)

# Dereference safe stack address and restore safe stack to %rsp
    mov safestack_base@GOTPCREL(%rip), %rbx
    mov (%rbx), %rbx
    mov %rbx, %rsp

# Copy over values from unsafe stack to safe stack:
    mov (%rax), %rax
    mov 0x38(%rax), %rbx # Push arg10
    push %rbx
    mov 0x30(%rax), %rbx # Push arg9
    push %rbx
    mov 0x28(%rax), %rbx # Push arg8
    push %rbx
    mov 0x20(%rax), %rbx # Push arg7
    push %rbx
    mov 0x8(%rax), %rbx  # Push old %rax
    push %rbx
    mov (%rax), %rbx     # Push slot number
    push %rbx

    add $0x10, %rax
    mov unsafestack@GOTPCREL(%rip), %rbx
    mov %rax, (%rbx)

# We don't need jump target anymore
# Get slot number, old %rax and %rbx still on stack
    pop %rax
    mov gotplt_address@GOTPCREL(%rip), %rbx
# index into gotplt_address array to call target func
    mov (%rbx,%rax,8),%rbx
# we now have old %rax value from stack, only old %rbx on stack
    pop %rax
    callq *%rbx

# Time to restore stack to original, ignore safestack
# Dereference unsafe stack address and restore unsafestack pointer
    mov unsafestack@GOTPCREL(%rip), %rbx
    mov (%rbx), %rsp

#Store rax into rbx before wrpkru
    mov %rax, %rbx
    mov    $0x10,%eax
    mov    $0x0,%ecx
    mov    $0x0,%edx
    wrpkru
# Restore rax
    mov %rbx, %rax
    pop %rbx

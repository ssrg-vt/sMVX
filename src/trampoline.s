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
# We need first argument for calling __tls_get_addr
# __tls_get_addr clobbers %rcx and %rdx so we need to store this before
# calling it, and pop after.
# Dereference unsafe stack address and store unsafestack pointer
    push %rdi
    push %rcx
    push %rdx
    leaq tls_unsafestack@tlsgd(%rip), %rdi
    call __tls_get_addr@plt
    pop %rdx
    pop %rcx
    pop %rdi
    mov %rsp, (%rax)
    mov %rax, %rbx

## Dereference safe stack address and restore safe stack to %rsp
    push %rdi
    push %rcx
    push %rdx
    leaq tls_safestack@tlsgd(%rip), %rdi
    call __tls_get_addr@plt
    pop %rdx
    pop %rcx
    pop %rdi
# Add immediate of 0x1000 to it because safestack size is 4096 bytes
# and stack grows towards lower memory.
    add $0x1000, %rax
    mov %rax, %rsp

## Copy over values from unsafe stack to safe stack:
#    mov (%rax), %rax
#    mov 0x38(%rax), %rbx # Push arg10
#    push %rbx
#    mov 0x30(%rax), %rbx # Push arg9
#    push %rbx
#    mov 0x28(%rax), %rbx # Push arg8
#    push %rbx
#    mov 0x20(%rax), %rbx # Push arg7
#    push %rbx
#    mov 0x8(%rax), %rbx  # Push old %rax
#    push %rbx
#    mov (%rax), %rbx     # Push slot number
#    push %rbx
#
#    add $0x10, %rax
#    mov unsafestack@GOTPCREL(%rip), %rbx
#    mov %rax, (%rbx)

# Copy over values from unsafe stack to safe stack:
    mov (%rbx), %rbx
    mov 0x38(%rbx), %rax # Push arg10
    push %rax
    mov 0x30(%rbx), %rax # Push arg9
    push %rax
    mov 0x28(%rbx), %rax # Push arg8
    push %rax
    mov 0x20(%rbx), %rax # Push arg7
    push %rax
    mov 0x8(%rbx), %rax  # Push old %rax
    push %rax
    mov (%rbx), %rax     # Push slot number
    push %rax

# Accounting, remove two entries from unsafestack because these will
# be popped in the safestack. We need to maintain consistency.
    add $0x10, %rbx

# Store unsafestack for later restoration
    push %rdi
    push %rcx
    push %rdx
    leaq tls_unsafestack@tlsgd(%rip), %rdi
    call __tls_get_addr@plt
    pop %rdx
    pop %rcx
    pop %rdi
    mov %rbx, (%rax)

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
    push %rdi
    push %rcx
    push %rdx
    push %rax
    leaq tls_unsafestack@tlsgd(%rip), %rdi
    call __tls_get_addr@plt
    mov %rax, %rbx
    pop %rax
    pop %rdx
    pop %rcx
    pop %rdi
    mov (%rbx), %rsp

#Store rax into rbx before wrpkru
    mov %rax, %rbx
    mov    $0x10,%eax
    #mov    $0x0,%eax
    mov    $0x0,%ecx
    mov    $0x0,%edx
    wrpkru
# Restore rax
    mov %rbx, %rax
    pop %rbx
    ret

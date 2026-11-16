/* A genuine ELF32 ARM EABI process for the AArch64 observer's foreign-ABI
 * checks. No libc, dynamic loader, interpreter or startup syscalls intervene.
 * argv[1] is a fresh sentinel. Exactly three foreign calls return something
 * other than ENOSYS: open, write, close. A deliberately nonexistent call must
 * return ENOSYS; exit does not return and therefore contributes no result.
 * Linux ARM EABI numbers are independent of the native AArch64 table.
 */
.syntax unified
.arm
.global _start
.type _start, %function
.section .text
_start:
    ldr r0, [sp]
    cmp r0, #2
    movne r0, #9
    bne finish

    ldr r0, [sp, #8]             /* argv[1] */
    mov r1, #193                 /* O_WRONLY | O_CREAT | O_EXCL */
    mov r2, #384                 /* 0600 */
    mov r7, #5                   /* ARM EABI open */
    svc #0
    cmp r0, #0
    movlt r0, #10
    blt finish
    mov r4, r0

    adr r1, sentinel
    mov r2, #6
    mov r7, #4                   /* ARM EABI write */
    svc #0
    cmp r0, #6
    movne r0, #11
    bne finish

    mov r0, r4
    mov r7, #6                   /* ARM EABI close */
    svc #0
    cmp r0, #0
    movne r0, #12
    bne finish

    movw r7, #0x7ffe             /* absent from the ARM EABI table */
    svc #0
    cmn r0, #38                  /* -ENOSYS */
    movne r0, #13
    bne finish
    mov r0, #0
finish:
    mov r7, #1                   /* ARM EABI exit */
    svc #0
    udf #0                      /* exit unexpectedly returned */
.size _start, .-_start
sentinel:
    .ascii "arm32\n"
.section .note.GNU-stack,"",%progbits

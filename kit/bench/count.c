/*
 * QEMU TCG plugin that counts every guest instruction executed by the program
 * run under qemu-arm -cpu cortex-a9 (Appendix A of the thesis).
 *
 * Build (bench/build_qemu_plugin.sh):
 *   gcc -shared -fPIC -O2 $(pkg-config --cflags glib-2.0) \
 *       -I $QEMU_SRC/include/qemu -o libcount.so count.c
 * Use:
 *   qemu-arm -cpu cortex-a9 -plugin ./libcount.so ./mavcrypt_tool_arm bench 36 20000 seal
 *   -> prints "insns: N" to stderr at exit.
 *
 * The cost per frame of one operation (seal or open, measured in separate runs)
 * is (I(20000) - I(0)) / 20000: everything outside the measured loop cancels.
 */
#include <stdio.h>
#include <inttypes.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static uint64_t insns;

static void tb_exec(unsigned int vcpu, void *n) { insns += (uintptr_t)n; }

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)(uintptr_t)qemu_plugin_tb_n_insns(tb));
}
static void at_exit(qemu_plugin_id_t id, void *p) {
    fprintf(stderr, "insns: %" PRIu64 "\n", insns);
}
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv) {
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    return 0;
}

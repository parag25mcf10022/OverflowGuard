// ============================================================================
// user1.cpp — Hypervisor Resource Manager
//
// Manages vCPU state, guest physical memory, MMIO regions, and I/O port
// handlers for a Type-1 bare-metal hypervisor.  Supports snapshot
// save/restore, address translation, APIC/UART/PCI port emulation, and a
// simple round-robin vCPU scheduler.
//
// Compile:
//   g++ -std=c++17 -O2 -o hv_rm user1.cpp
// With AddressSanitizer:
//   g++ -std=c++17 -O1 -fsanitize=address,undefined -o hv_rm_asan user1.cpp
// ============================================================================

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cassert>
#include <functional>
#include <iomanip>

// ── Compile-time constants ──────────────────────────────────────────────────
static constexpr uint32_t HV_MAX_VMS           = 64;
static constexpr uint32_t HV_MAX_VCPUS_PER_VM  = 32;
static constexpr uint32_t MAX_MMIO_REGIONS      = 16;
static constexpr uint32_t MAX_IOPORT_HANDLERS   = 256;
static constexpr uint32_t PAGE_SIZE             = 4096;
static constexpr uint32_t VCPU_REGISTER_COUNT   = 16;
static constexpr uint32_t VM_NAME_LEN           = 64;
static constexpr uint32_t SNAPSHOT_MAGIC        = 0xDEAD1337;
static constexpr uint32_t MAX_PENDING_IRQS      = 8;

// ── Register file ───────────────────────────────────────────────────────────
struct RegisterFile {
    uint64_t gpr[VCPU_REGISTER_COUNT];   // rax–r15
    uint64_t rip;
    uint64_t rflags;
    uint64_t cr0, cr3, cr4;
    uint64_t efer;
    uint64_t dr[8];                      // debug registers
};

// ── vCPU state ──────────────────────────────────────────────────────────────
struct VCPUState {
    uint32_t     vcpu_id;
    uint32_t     vm_id;
    bool         running;
    bool         halted;
    uint8_t      _pad0[2];
    RegisterFile regs;
    uint8_t      fpu_state[512];         // FXSAVE area (512 bytes aligned)
    uint64_t     tsc_offset;
    uint64_t     vmcs_ptr;               // host-physical VMCS pointer
    uint32_t     apic_id;
    uint32_t     pending_irqs[MAX_PENDING_IRQS];
    uint32_t     irq_head;               // ring-buffer head index
    uint32_t     irq_tail;               // ring-buffer tail index
    uint8_t      _pad1[4];
};

// ── MMIO region ─────────────────────────────────────────────────────────────
struct MmioRegion {
    uint64_t guest_phys;
    uint64_t host_virt;
    uint64_t length;
    uint32_t flags;                      // bit 0=R, bit 1=W, bit 2=X
    bool     mapped;
    uint8_t  _pad[3];
};

// ── I/O port handler entry ──────────────────────────────────────────────────
using IoHandler = std::function<void(uint16_t port, uint32_t &val, bool is_write)>;

struct IoEntry {
    uint16_t  port;
    bool      active;
    uint8_t   _pad;
    IoHandler handler;
};

// ── Snapshot header (serialised to flat byte buffer) ────────────────────────
//
//   Layout on disk / in-memory:
//     [ SnapshotHeader | VCPUState[0] | VCPUState[1] | ... ]
//
//   VULNERABILITY NOTE (hidden):
//     data_length is uint16_t.  It is assigned from
//     (num_vcpus * sizeof(VCPUState)) in snapshot_save().
//     For 32 vCPUs: 32 * sizeof(VCPUState) can exceed 65535 depending on
//     platform padding, silently truncating.  The restore path allocates
//     exactly data_length bytes but then writes num_vcpus * sizeof(VCPUState)
//     bytes, making a crafted header (small data_length, large num_vcpus) a
//     heap overflow trigger that bypasses the CRC check (CRC covers the
//     payload bytes, not the header fields).
//
struct SnapshotHeader {
    uint32_t magic;
    uint16_t num_vcpus;        // number of vCPU records that follow
    uint16_t data_length;      // total byte length of all vCPU records
    uint32_t crc32;
    uint8_t  vm_name[VM_NAME_LEN];
};

// ── VM descriptor ────────────────────────────────────────────────────────────
struct VMDescriptor {
    uint32_t   vm_id;
    bool       active;
    uint8_t    _pad[3];
    char       name[VM_NAME_LEN];
    uint64_t   mem_size;         // guest physical RAM (bytes)
    uint8_t   *mem_base;         // host pointer to guest RAM

    uint16_t   num_vcpus;
    uint8_t    _pad2[6];
    VCPUState *vcpus;

    // The array is sized MAX_MMIO_REGIONS + 1.
    // The extra slot looks like defensive padding; it is the silent landing
    // zone for the off-by-one write in mmio_register() — see BUG-B.
    MmioRegion mmio[MAX_MMIO_REGIONS + 1];
    uint32_t   mmio_count;

    IoEntry  io_ports[MAX_IOPORT_HANDLERS];
    uint32_t io_count;

    uint64_t stats_exits_total;
    uint64_t stats_mmio_exits;
    uint64_t stats_pio_exits;
};

// ── Global VM table ─────────────────────────────────────────────────────────
static VMDescriptor g_vms[HV_MAX_VMS];
static uint32_t     g_vm_count = 0;

// ============================================================================
// Utility: compact CRC-32 (polynomial 0xEDB88320)
// ============================================================================
static uint32_t crc32_buf(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b)
            crc = (crc >> 1) ^ (0xEDB88320u & static_cast<uint32_t>(-(crc & 1)));
    }
    return ~crc;
}

// ============================================================================
// vm_create — allocate a new VM slot and its resources
//
//  @vm_id       unique identifier for this VM
//  @name        human-readable label (at most VM_NAME_LEN-1 chars)
//  @mem_size_mb guest RAM in mebibytes
//  @num_vcpus   number of virtual CPUs to provision
//
//  Returns 0 on success, negative on error.
// ============================================================================
int vm_create(uint32_t vm_id, const char *name,
              uint64_t mem_size_mb, uint16_t num_vcpus)
{
    if (g_vm_count >= HV_MAX_VMS)                    return -1;
    if (num_vcpus == 0 || num_vcpus > HV_MAX_VCPUS_PER_VM) return -2;

    VMDescriptor &vm = g_vms[g_vm_count];
    std::memset(&vm, 0, sizeof(VMDescriptor));

    vm.vm_id    = vm_id;
    vm.active   = true;
    vm.mem_size = mem_size_mb * 1024ULL * 1024ULL;

    std::strncpy(vm.name, name, VM_NAME_LEN - 1);

    // Allocate guest RAM (zeroed)
    vm.mem_base = static_cast<uint8_t *>(std::calloc(1, vm.mem_size));
    if (!vm.mem_base) return -3;

    vm.num_vcpus = num_vcpus;

    // Allocate vCPU array.
    // For normal num_vcpus values (≤ HV_MAX_VCPUS_PER_VM = 32) this is safe.
    // The overflow surface lies in snapshot_restore(), where num_vcpus comes
    // from an untrusted header field and vm->vcpus is replaced after the fact.
    vm.vcpus = static_cast<VCPUState *>(
        std::malloc(static_cast<size_t>(num_vcpus) * sizeof(VCPUState)));
    if (!vm.vcpus) {
        std::free(vm.mem_base);
        return -4;
    }

    for (uint16_t i = 0; i < num_vcpus; ++i) {
        std::memset(&vm.vcpus[i], 0, sizeof(VCPUState));
        vm.vcpus[i].vcpu_id  = i;
        vm.vcpus[i].vm_id    = vm_id;
        vm.vcpus[i].apic_id  = (vm_id << 8) | i;
        vm.vcpus[i].irq_head = 0;
        vm.vcpus[i].irq_tail = 0;
    }

    g_vm_count++;
    return 0;
}

// ============================================================================
// mmio_register — map a guest physical range to a fresh host buffer
//
//  Returns 0 on success, negative on error.
//
//  BUG-B (off-by-one in duplicate-check loop):
//    The scan for duplicate guest_phys addresses uses:
//      for (uint32_t i = 0; i <= MAX_MMIO_REGIONS; i++)
//    MAX_MMIO_REGIONS = 16, array has 17 slots (indices 0..16).
//    When mmio_count == 16 (array full), the loop's final iteration reads
//    vm->mmio[16] — the extra "+1" slot.  If that slot was partially written
//    by a concurrent insert or a stale value from a destroyed-and-recreated VM,
//    the mapped/guest_phys comparison can produce a spurious hit (false
//    "already registered") or — worse — the loop falls through and the insert
//    writes into mmio[16] a second time via vm->mmio[vm->mmio_count++] in the
//    same call, overlapping with the first field of io_ports[] in the struct
//    layout.  This is extremely hard to trigger under normal workloads because
//    it requires exactly max capacity plus a zero-value stale slot.
// ============================================================================
int mmio_register(uint32_t vm_id, uint64_t guest_phys,
                  uint64_t length, uint32_t flags)
{
    VMDescriptor *vm = nullptr;
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        if (g_vms[i].vm_id == vm_id && g_vms[i].active) {
            vm = &g_vms[i];
            break;
        }
    }
    if (!vm) return -1;
    if (length == 0 || length > (1ULL << 30)) return -2; // sanity: ≤ 1 GiB

    // Scan for duplicate GPA — loop bound is <= instead of <  (BUG-B)
    for (uint32_t i = 0; i <= MAX_MMIO_REGIONS; ++i) {
        if (vm->mmio[i].mapped && vm->mmio[i].guest_phys == guest_phys)
            return -3; // already registered at this guest physical base
    }

    if (vm->mmio_count >= MAX_MMIO_REGIONS) return -4; // no free slots

    void *host_mem = std::calloc(1, length);
    if (!host_mem) return -5;

    MmioRegion &r = vm->mmio[vm->mmio_count++];
    r.guest_phys  = guest_phys;
    r.host_virt   = reinterpret_cast<uint64_t>(host_mem);
    r.length      = length;
    r.flags       = flags;
    r.mapped      = true;

    return 0;
}

// ============================================================================
// ioport_register — attach a software handler to a guest I/O port
// ============================================================================
int ioport_register(uint32_t vm_id, uint16_t port, IoHandler handler)
{
    VMDescriptor *vm = nullptr;
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        if (g_vms[i].vm_id == vm_id && g_vms[i].active) {
            vm = &g_vms[i];
            break;
        }
    }
    if (!vm) return -1;
    if (vm->io_count >= MAX_IOPORT_HANDLERS) return -2;

    IoEntry &e = vm->io_ports[vm->io_count++];
    e.port    = port;
    e.active  = true;
    e.handler = handler;
    return 0;
}

// ============================================================================
// ioport_dispatch — route a guest port-IO VM-exit to the registered handler
//
//  BUG-C (hidden, OOB read via corrupted io_count):
//    io_count is stored in the VMDescriptor and incremented in
//    ioport_register().  In a complete VMM, hot-plug device emulation may
//    increment io_count via a separate code path; if that path has a TOCTOU
//    or wrapping bug, io_count can exceed MAX_IOPORT_HANDLERS.  The loop here
//    uses `i < vm->io_count` as its bound, so a vm->io_count of 300 causes
//    reads of io_ports[256..299], which lie inside subsequent struct fields
//    (stats_exits_total, stats_mmio_exits, etc.).  The IoEntry::active bool
//    comparison against those bytes rarely produces a false match but does
//    constitute an out-of-bounds read on every dispatch call once io_count
//    has been corrupted.
// ============================================================================
void ioport_dispatch(uint32_t vm_id, uint16_t port,
                     uint32_t &val, bool is_write)
{
    VMDescriptor *vm = nullptr;
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        if (g_vms[i].vm_id == vm_id && g_vms[i].active) {
            vm = &g_vms[i];
            break;
        }
    }
    if (!vm) return;

    vm->stats_exits_total++;
    vm->stats_pio_exits++;

    for (uint32_t i = 0; i < vm->io_count; ++i) {
        if (vm->io_ports[i].active && vm->io_ports[i].port == port) {
            vm->io_ports[i].handler(port, val, is_write);
            return;
        }
    }
    // Unhandled port — default: reads return 0xFF (open bus), writes ignored
    if (!is_write) val = 0xFFFFFFFFu;
}

// ============================================================================
// irq_inject — push a virtual interrupt into a vCPU's pending ring buffer
//
//  BUG-D (hidden, integer wraparound in ring-buffer index):
//    irq_tail is uint32_t.  The modulo expression
//      (irq_tail + 1) % MAX_PENDING_IRQS
//    is evaluated in 32-bit arithmetic, which is correct.  However, if
//    irq_tail has been incremented without modulo reduction from a separate
//    code path (e.g., a bulk-inject helper not shown here), it can reach
//    UINT32_MAX.  (UINT32_MAX + 1) wraps to 0 in uint32_t, so the modulo
//    then equals 0 — no overflow in the index itself.  But the slot written is
//    pending_irqs[0], silently discarding the previous entry at slot 0 rather
//    than detecting the full-buffer condition.  Under sustained interrupt
//    storms this causes silent IRQ loss, not a memory safety issue in isolation.
//    The overflow becomes dangerous when irq_tail is used as a direct array
//    index in a hypothetical fast-path that skips the modulo:
//      vcpu->pending_irqs[vcpu->irq_tail] = vector;   <-- if irq_tail≥8: OOB
// ============================================================================
int irq_inject(uint32_t vm_id, uint32_t vcpu_idx, uint32_t vector)
{
    VMDescriptor *vm = nullptr;
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        if (g_vms[i].vm_id == vm_id && g_vms[i].active) {
            vm = &g_vms[i];
            break;
        }
    }
    if (!vm || vcpu_idx >= vm->num_vcpus) return -1;

    VCPUState &vcpu = vm->vcpus[vcpu_idx];
    uint32_t next   = (vcpu.irq_tail + 1) % MAX_PENDING_IRQS;
    if (next == vcpu.irq_head) return -2; // ring buffer full

    vcpu.pending_irqs[vcpu.irq_tail] = vector;
    vcpu.irq_tail = next;
    return 0;
}

// ============================================================================
// vcpu_run_batch — simulate one scheduling quantum for every vCPU in a VM
// ============================================================================
void vcpu_run_batch(uint32_t vm_id, uint32_t ticks)
{
    VMDescriptor *vm = nullptr;
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        if (g_vms[i].vm_id == vm_id && g_vms[i].active) {
            vm = &g_vms[i];
            break;
        }
    }
    if (!vm) return;

    for (uint16_t i = 0; i < vm->num_vcpus; ++i) {
        VCPUState &vcpu = vm->vcpus[i];
        if (vcpu.halted) continue;

        vcpu.running     = true;
        vcpu.tsc_offset += ticks;
        // Advance RIP to simulate instruction execution
        vcpu.regs.rip   += (ticks & 0xFFF);
        // Drain one pending IRQ per quantum (simplified APIC model)
        if (vcpu.irq_head != vcpu.irq_tail) {
            uint32_t vec = vcpu.pending_irqs[vcpu.irq_head];
            vcpu.irq_head = (vcpu.irq_head + 1) % MAX_PENDING_IRQS;
            (void)vec; // would be dispatched to IDT in a real VMM
        }
        vcpu.running = false;
        vm->stats_exits_total++;
    }
}

// ============================================================================
// snapshot_save — serialise all vCPU states to a caller-owned flat buffer
//
//  Returns a malloc'd buffer; caller must free().  Sets *out_size on success.
// ============================================================================
uint8_t *snapshot_save(uint32_t vm_id, size_t *out_size)
{
    if (!out_size) return nullptr;

    VMDescriptor *vm = nullptr;
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        if (g_vms[i].vm_id == vm_id && g_vms[i].active) {
            vm = &g_vms[i];
            break;
        }
    }
    if (!vm) return nullptr;

    size_t   body_size = static_cast<size_t>(vm->num_vcpus) * sizeof(VCPUState);
    size_t   total     = sizeof(SnapshotHeader) + body_size;
    uint8_t *buf       = static_cast<uint8_t *>(std::malloc(total));
    if (!buf) return nullptr;

    SnapshotHeader *hdr = reinterpret_cast<SnapshotHeader *>(buf);
    hdr->magic          = SNAPSHOT_MAGIC;
    hdr->num_vcpus      = vm->num_vcpus;

    // BUG-A (hidden, silent truncation):
    //   body_size is size_t; hdr->data_length is uint16_t.
    //   For vm->num_vcpus = 32: body_size = 32 * sizeof(VCPUState).
    //   sizeof(VCPUState) is roughly 680+ bytes on x86-64, so body_size ≈ 21760,
    //   which fits in uint16_t (max 65535) — the bug is latent here.
    //   The dangerous case is in snapshot_restore(): if data_length is then
    //   artificially set to a small value in a crafted snapshot on disk,
    //   restore allocates data_length bytes but copies num_vcpus * sizeof(VCPUState)
    //   bytes, causing a heap overflow proportional to the discrepancy.
    hdr->data_length    = static_cast<uint16_t>(body_size);  // latent truncation

    std::strncpy(reinterpret_cast<char *>(hdr->vm_name), vm->name, VM_NAME_LEN - 1);

    uint8_t *payload = buf + sizeof(SnapshotHeader);
    for (uint16_t i = 0; i < vm->num_vcpus; ++i)
        std::memcpy(payload + i * sizeof(VCPUState),
                    &vm->vcpus[i], sizeof(VCPUState));

    hdr->crc32 = crc32_buf(payload, body_size);
    *out_size  = total;
    return buf;
}

// ============================================================================
// snapshot_restore — deserialise vCPU states from an external byte buffer
//
//  BUG-A (triggered here, hidden in size arithmetic):
//    The malloc below uses hdr->data_length (a uint16_t from the untrusted
//    header) as the allocation size.  The subsequent copy loop iterates
//    hdr->num_vcpus times, writing sizeof(VCPUState) bytes per iteration — a
//    total of (num_vcpus * sizeof(VCPUState)) bytes.  When data_length has been
//    tampered to be smaller than that product, the heap buffer is overflowed.
//
//    The CRC check runs over the first data_length bytes of payload, so a
//    crafted snapshot needs only a valid CRC over those bytes — it does not
//    protect against mismatched (num_vcpus, data_length) pairs.
//
//    Detection is near-impossible via static analysis because:
//      1. The allocation and the loop are 10+ lines apart.
//      2. Both use typed fields that appear correctly bounded at first glance.
//      3. The only guard is the CRC, which an attacker can recalculate.
// ============================================================================
int snapshot_restore(uint32_t vm_id, const uint8_t *buf, size_t buf_len)
{
    if (!buf || buf_len < sizeof(SnapshotHeader)) return -1;

    const SnapshotHeader *hdr = reinterpret_cast<const SnapshotHeader *>(buf);
    if (hdr->magic != SNAPSHOT_MAGIC)                    return -2;
    if (hdr->num_vcpus == 0 ||
        hdr->num_vcpus > HV_MAX_VCPUS_PER_VM)            return -3;

    VMDescriptor *vm = nullptr;
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        if (g_vms[i].vm_id == vm_id && g_vms[i].active) {
            vm = &g_vms[i];
            break;
        }
    }
    if (!vm) return -4;

    // Validate that the reported data fits within the supplied buffer
    if (sizeof(SnapshotHeader) + hdr->data_length > buf_len) return -5;

    const uint8_t *payload = buf + sizeof(SnapshotHeader);

    // CRC covers exactly data_length bytes — does NOT cover num_vcpus
    uint32_t crc = crc32_buf(payload, hdr->data_length);
    if (crc != hdr->crc32) return -6;

    // Allocate restoration buffer sized by data_length (untrusted uint16_t).
    // num_vcpus * sizeof(VCPUState) may exceed this — heap overflow (BUG-A).
    size_t   alloc_size = static_cast<size_t>(hdr->data_length);
    uint8_t *vcpu_buf   = static_cast<uint8_t *>(std::malloc(alloc_size + 1));
    if (!vcpu_buf) return -7;

    // Loop iterates num_vcpus times, each writing sizeof(VCPUState) bytes.
    // If alloc_size < num_vcpus * sizeof(VCPUState) this overflows the buffer.
    for (uint16_t i = 0; i < hdr->num_vcpus; ++i) {
        std::memcpy(vcpu_buf + static_cast<size_t>(i) * sizeof(VCPUState),
                    payload  + static_cast<size_t>(i) * sizeof(VCPUState),
                    sizeof(VCPUState));
    }

    // Swap in the restored vCPU array
    if (vm->vcpus) std::free(vm->vcpus);
    vm->num_vcpus = hdr->num_vcpus;
    vm->vcpus     = reinterpret_cast<VCPUState *>(vcpu_buf);
    return 0;
}

// ============================================================================
// mem_translate — convert a guest physical address to a host virtual pointer
//
//  BUG-E (hidden, off-by-one in MMIO scan):
//    The loop uses `i <= vm->mmio_count` instead of `i < vm->mmio_count`.
//    When all slots are full (mmio_count == MAX_MMIO_REGIONS = 16), the final
//    iteration reads vm->mmio[16] — the extra slot at index MAX_MMIO_REGIONS.
//    In normal operation that slot is zeroed (mapped == false) and the loop
//    terminates cleanly.  However, if the off-by-one write in mmio_register()
//    (BUG-B) has written valid-looking data into slot 16 during a full-table
//    concurrent insert, this function may return a host_virt pointer derived
//    from stale/attacker-influenced data, leading to an arbitrary host memory
//    write when the caller subsequently writes to the translated address.
// ============================================================================
uint8_t *mem_translate(uint32_t vm_id, uint64_t gpa, uint32_t access_len)
{
    VMDescriptor *vm = nullptr;
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        if (g_vms[i].vm_id == vm_id && g_vms[i].active) {
            vm = &g_vms[i];
            break;
        }
    }
    if (!vm) return nullptr;

    vm->stats_mmio_exits++;

    // Check registered MMIO regions — BUG-E: <= instead of <
    for (uint32_t i = 0; i <= vm->mmio_count; ++i) {
        const MmioRegion &r = vm->mmio[i];
        if (r.mapped &&
            gpa >= r.guest_phys &&
            gpa + access_len <= r.guest_phys + r.length)
        {
            return reinterpret_cast<uint8_t *>(r.host_virt) +
                   (gpa - r.guest_phys);
        }
    }

    // Fall through to guest RAM (identity-mapped from GPA 0)
    if (!vm->mem_base) return nullptr;
    if (gpa + access_len > vm->mem_size) return nullptr; // out of RAM range
    return vm->mem_base + gpa;
}

// ============================================================================
// vm_stats — print runtime counters for a VM
// ============================================================================
void vm_stats(uint32_t vm_id)
{
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        const VMDescriptor &vm = g_vms[i];
        if (vm.vm_id != vm_id || !vm.active) continue;

        std::cout << "  [stats] vm=" << vm_id
                  << " exits_total=" << vm.stats_exits_total
                  << " mmio="        << vm.stats_mmio_exits
                  << " pio="         << vm.stats_pio_exits
                  << "\n";
        return;
    }
}

// ============================================================================
// print_vm_info — dump VM descriptor and per-vCPU state to stdout
// ============================================================================
void print_vm_info(uint32_t vm_id)
{
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        VMDescriptor &vm = g_vms[i];
        if (vm.vm_id != vm_id || !vm.active) continue;

        std::cout << "\n=== VM #" << vm_id << " [" << vm.name << "] ===\n"
                  << "  RAM     : " << (vm.mem_size >> 20) << " MiB\n"
                  << "  vCPUs   : " << vm.num_vcpus    << "\n"
                  << "  MMIO    : " << vm.mmio_count   << " region(s)\n"
                  << "  I/O     : " << vm.io_count     << " handler(s)\n";

        for (uint16_t v = 0; v < vm.num_vcpus; ++v) {
            const VCPUState &c = vm.vcpus[v];
            std::cout << "  vCPU["  << v << "]"
                      << " rip=0x"  << std::hex << std::setw(16) << std::setfill('0')
                      << c.regs.rip
                      << " tsc=0x"  << c.tsc_offset
                      << " apic=0x" << c.apic_id
                      << std::dec;
            if (c.halted)  std::cout << " [HALTED]";
            if (c.running) std::cout << " [RUNNING]";
            uint32_t pending = (c.irq_tail - c.irq_head) % MAX_PENDING_IRQS;
            if (pending)   std::cout << " irq_pending=" << pending;
            std::cout << "\n";
        }
        return;
    }
    std::cout << "VM #" << vm_id << " not found.\n";
}

// ============================================================================
// vm_destroy — release all heap resources for a VM slot
// ============================================================================
void vm_destroy(uint32_t vm_id)
{
    for (uint32_t i = 0; i < g_vm_count; ++i) {
        VMDescriptor &vm = g_vms[i];
        if (vm.vm_id != vm_id || !vm.active) continue;

        for (uint32_t j = 0; j < vm.mmio_count; ++j) {
            if (vm.mmio[j].mapped) {
                std::free(reinterpret_cast<void *>(vm.mmio[j].host_virt));
                vm.mmio[j].mapped = false;
            }
        }

        if (vm.vcpus)    { std::free(vm.vcpus);    vm.vcpus    = nullptr; }
        if (vm.mem_base) { std::free(vm.mem_base);  vm.mem_base  = nullptr; }
        vm.active = false;
        return;
    }
}

// ============================================================================
// main — exercise the resource manager
// ============================================================================
int main()
{
    std::cout << "[HV] Hypervisor resource manager initialising\n";

    // ── Create VM 1: 128 MiB RAM, 4 vCPUs ──────────────────────────────────
    if (vm_create(1, "guest-linux", 128, 4) != 0) {
        std::cerr << "[HV] ERROR: failed to create VM 1\n";
        return 1;
    }

    // Register MMIO regions
    mmio_register(1, 0xFEE00000ULL, 0x1000,   0x3);   // Local APIC
    mmio_register(1, 0xFEC00000ULL, 0x1000,   0x3);   // I/O APIC
    mmio_register(1, 0xE0000000ULL, 0x100000, 0x3);   // PCI ECAM

    // Register I/O port handlers
    ioport_register(1, 0x3F8, [](uint16_t, uint32_t &v, bool w) {
        if (w) std::cout << "  [UART0] TX byte: 0x"
                         << std::hex << (v & 0xFF) << std::dec << "\n";
        else   v = 0xFF; // no data available
    });
    ioport_register(1, 0xCF8, [](uint16_t, uint32_t &v, bool w) {
        if (w) std::cout << "  [PCI]  CONFIG_ADDRESS <- 0x"
                         << std::hex << v << std::dec << "\n";
    });
    ioport_register(1, 0xCFC, [](uint16_t, uint32_t &v, bool w) {
        if (!w) v = 0x11112222u; // fake vendor/device ID
    });

    // Inject a couple of test IRQs
    irq_inject(1, 0, 0x20); // timer IRQ to vCPU 0
    irq_inject(1, 1, 0x21); // keyboard IRQ to vCPU 1

    // Run scheduling batch
    vcpu_run_batch(1, 10000);
    print_vm_info(1);
    vm_stats(1);

    // ── Snapshot round-trip (legitimate path) ──────────────────────────────
    size_t   snap_size = 0;
    uint8_t *snap      = snapshot_save(1, &snap_size);
    if (snap) {
        std::cout << "\n[HV] Snapshot saved: " << snap_size << " bytes"
                  << " (header=" << sizeof(SnapshotHeader) << ")\n";
        int rc = snapshot_restore(1, snap, snap_size);
        std::cout << "[HV] Snapshot restore: rc=" << rc << "\n";
        std::free(snap);
    }

    // ── Port-IO dispatch ────────────────────────────────────────────────────
    uint32_t val = 0x41; // 'A'
    ioport_dispatch(1, 0x3F8, val, true);
    ioport_dispatch(1, 0xCFC, val, false);
    std::cout << "  [PCI]  CONFIG_DATA  -> 0x" << std::hex << val
              << std::dec << "\n";

    // ── Address translation ─────────────────────────────────────────────────
    uint8_t *hptr = mem_translate(1, 0x1000, 4);
    if (hptr) {
        std::cout << "\n[HV] GPA 0x1000 -> HVA 0x"
                  << std::hex << reinterpret_cast<uintptr_t>(hptr)
                  << std::dec << "\n";
        // Simulate a guest writing a page-table entry
        hptr[0] = 0x03; hptr[1] = 0x10; hptr[2] = 0x00; hptr[3] = 0x00;
    }

    // ── Create VM 2: 256 MiB, 2 vCPUs ──────────────────────────────────────
    if (vm_create(2, "guest-windows", 256, 2) == 0) {
        mmio_register(2, 0xFEE00000ULL, 0x1000, 0x3);
        ioport_register(2, 0x3F8, [](uint16_t, uint32_t &v, bool w) {
            if (w) std::cout << "  [VM2 UART] TX: 0x"
                             << std::hex << (v & 0xFF) << std::dec << "\n";
            else   v = 0xFF;
        });
        vcpu_run_batch(2, 5000);
        print_vm_info(2);
        vm_stats(2);
    }

    // ── Cleanup ─────────────────────────────────────────────────────────────
    vm_destroy(1);
    vm_destroy(2);
    std::cout << "\n[HV] Resource manager shutdown complete.\n";
    return 0;
}

/**
 * One computer per slot, created by the closed kin-computer binary before the
 * guest starts. The algorithm and device codes stay in that binary.
 * Hostname and the 32-bit machine-id come from the directory it writes.
 * device_id stays a control-plane 64-bit value and is never the SMBIOS UUID.
 */
import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { isKvmRuntime } from '../vm/runtime-kind.mjs'
import { atomicWriteJson } from '../vm/vm-file.mjs'
import {
  generateWorkstationFingerprint,
  HOSTNAME_RE,
  isPlaceholderHostname,
  MACHINE_ID_RE,
} from './workstation-fingerprint.mjs'
import { isRfc4122Uuid } from './rfc4122-uuid.mjs'
import { repairKvmFingerprintUuid } from './kvm-fingerprint-uuid.mjs'

const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')

export function computerBin() {
  const fromEnv = String(process.env.KIN_COMPUTER_BIN || '').trim()
  if (fromEnv) return fromEnv
  return path.join(REPO_ROOT, 'bin', 'kin-computer')
}

export function fingerprintDir(projectRoot, vmId) {
  return path.join(projectRoot, 'vms', vmId, 'kvm', 'fingerprint')
}

function readTrimmed(file) {
  return fs.readFileSync(file, 'utf8').replace(/\s+/g, '')
}

function linuxComputer(dir) {
  const identPath = path.join(dir, 'identity.json')
  const smbios = path.join(dir, 'qemu-smbios.args')
  if (!fs.existsSync(identPath) || !fs.existsSync(smbios)) return null
  let data
  try {
    data = JSON.parse(fs.readFileSync(identPath, 'utf8'))
  } catch {
    return null
  }
  const hostname = String(data.hostname || '').trim()
  const guest_machine_id = String(data.machine_id || '')
    .trim()
    .toLowerCase()
  const uuid = String(data.uuid || '').trim()
  if (!HOSTNAME_RE.test(hostname) || !MACHINE_ID_RE.test(guest_machine_id) || !isRfc4122Uuid(uuid)) return null
  try {
    if (!fs.statSync(smbios).size) return null
  } catch {
    return null
  }
  return { hostname, guest_machine_id, mac: '', dir, kvm: true }
}

function containerComputer(dir) {
  const hostFile = path.join(dir, 'system', 'etc', 'hostname')
  const midFile = path.join(dir, 'system', 'etc', 'machine-id')
  const macFile = path.join(dir, 'system', 'hardware', 'mac')
  const dmi = path.join(dir, 'system', 'dmi', 'id')
  for (const file of [hostFile, midFile, macFile]) {
    try {
      if (!fs.statSync(file).isFile()) return null
    } catch {
      return null
    }
  }
  try {
    if (!fs.statSync(dmi).isDirectory()) return null
  } catch {
    return null
  }
  const hostname = readTrimmed(hostFile)
  const guest_machine_id = readTrimmed(midFile).toLowerCase()
  const mac = readTrimmed(macFile).toLowerCase()
  if (!HOSTNAME_RE.test(hostname) || !MACHINE_ID_RE.test(guest_machine_id) || !MAC_RE.test(mac)) return null
  return { hostname, guest_machine_id, mac, dir, kvm: false }
}

function runChecked(argv, timeout) {
  try {
    execFileSync(argv[0], argv.slice(1), {
      encoding: 'utf8',
      timeout,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
  } catch (e) {
    const detail = String(e.stderr || e.stdout || e.message || e).trim()
    throw new Error(detail || 'vm-os computer identity failed')
  }
}

/**
 * A replacement hostname, or '' when the current one may stay. Placeholders come
 * from a QEMU/DMI default; a value already on another slot collides.
 */
function nextHostname(vm, current, taken) {
  if (!isPlaceholderHostname(current) && !taken?.hostname?.has(current)) return ''
  return generateWorkstationFingerprint(vm, { taken }).hostname
}

function writeHostname(dir, kvm, hostname) {
  if (kvm) {
    const file = path.join(dir, 'identity.json')
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'))
    doc.hostname = hostname
    atomicWriteJson(file, doc, { mode: 0o600 })
    return
  }
  fs.mkdirSync(path.join(dir, 'system', 'etc'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'system', 'etc', 'hostname'), `${hostname}\n`)
}

/** Repair a placeholder hostname on an existing slot so a second ensure heals it. */
function repairHostname(dir, kvm, computer, vm, taken) {
  const hostname = nextHostname(vm, computer.hostname, taken)
  if (!hostname) return computer
  writeHostname(dir, kvm, hostname)
  return { ...computer, hostname }
}

/**
 * The binary derives identity from --vm-id, so a recreated slot would inherit the
 * deleted slot's machine-id. Mint the machine-id (and the Docker MAC) here, and
 * replace a placeholder/colliding hostname; keep a legitimate DMI-derived name.
 */
function mintComputerIdentity(dir, kvm, vm, taken) {
  const machineId = crypto.randomBytes(16).toString('hex')
  if (kvm) {
    const file = path.join(dir, 'identity.json')
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'))
    doc.machine_id = machineId
    const hostname = nextHostname(vm, String(doc.hostname || '').trim(), taken)
    if (hostname) doc.hostname = hostname
    atomicWriteJson(file, doc, { mode: 0o600 })
    return
  }
  const etc = path.join(dir, 'system', 'etc')
  fs.mkdirSync(etc, { recursive: true })
  fs.writeFileSync(path.join(etc, 'machine-id'), `${machineId}\n`)
  const hostFile = path.join(etc, 'hostname')
  const cur = fs.existsSync(hostFile) ? fs.readFileSync(hostFile, 'utf8').trim() : ''
  const hostname = cur ? nextHostname(vm, cur, taken) : ''
  if (hostname) fs.writeFileSync(hostFile, `${hostname}\n`)
  const b = crypto.randomBytes(6)
  b[0] = (b[0] & 0xfe) | 0x02 // unicast, locally administered
  fs.mkdirSync(path.join(dir, 'system', 'hardware'), { recursive: true })
  fs.writeFileSync(
    path.join(dir, 'system', 'hardware', 'mac'),
    `${[...b].map((x) => x.toString(16).padStart(2, '0')).join(':')}\n`,
  )
}

/**
 * Read an existing computer. Create it once when the directory has no identity.
 * Reading is idempotent and must not run the binary again; a constructor call
 * (assignComputerFingerprint) passes fresh and mints over the binary's vm-id pick.
 */
export function ensureSlotComputer(projectRoot, vm, { fresh = false, taken } = {}) {
  if (!projectRoot || !vm?.id) throw new Error('projectRoot and vm id required')
  const kvm = isKvmRuntime(vm)
  const dir = fingerprintDir(projectRoot, vm.id)
  if (!fresh) {
    const ready = kvm ? linuxComputer(dir) : containerComputer(dir)
    if (ready) return { ...repairHostname(dir, kvm, ready, vm, taken), created: false }
    if (kvm && fs.existsSync(dir)) {
      repairKvmFingerprintUuid(dir)
      const repaired = linuxComputer(dir)
      if (repaired) return { ...repairHostname(dir, kvm, repaired, vm, taken), created: false }
    }
  }
  const bin = computerBin()
  if (!fs.existsSync(bin)) {
    const missing = new Error('计算机服务未安装。放好 kin-computer 后可再次创建，已完成的身份不会重抽。')
    missing.code = 'computer_service_missing'
    throw missing
  }
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true })
  fs.mkdirSync(dir, { recursive: true })
  try {
    runChecked(
      [bin, 'create', '--runtime', kvm ? 'kvm' : 'docker', '--vm-id', vm.id, '--out', dir],
      kvm ? 120_000 : 180_000,
    )
  } catch (e) {
    fs.rmSync(dir, { recursive: true, force: true })
    const failed = new Error(`计算机身份创建失败，目录已清掉，可再次创建：${String(e.message || e).slice(0, 240)}`)
    failed.code = 'computer_create_failed'
    throw failed
  }
  if (kvm) repairKvmFingerprintUuid(dir)
  if (fresh) mintComputerIdentity(dir, kvm, vm, taken)
  let written = kvm ? linuxComputer(dir) : containerComputer(dir)
  if (!written) {
    fs.rmSync(dir, { recursive: true, force: true })
    const incomplete = new Error('计算机身份不完整，目录已清掉，可再次创建。')
    incomplete.code = 'computer_create_failed'
    throw incomplete
  }
  // The closed binary can echo a DMI placeholder; never hand one back.
  written = repairHostname(dir, kvm, written, vm, taken)
  return { ...written, created: true }
}

/** Control-plane device_id plus the computer hostname and machine-id. */
export function assignComputerFingerprint(projectRoot, vm, { taken, now } = {}) {
  // fresh: never adopt the previous slot's identity for a reused vm id.
  const computer = ensureSlotComputer(projectRoot, vm, { fresh: true, taken })
  const generated = generateWorkstationFingerprint(vm, { taken, now })
  return {
    ...generated,
    hostname: computer.hostname,
    guest_machine_id: computer.guest_machine_id,
  }
}

/** Point the slot record at the computer. Does not touch device_id. */
export function rememberComputer(projectRoot, vm, computer) {
  if (!computer?.hostname || !vm?.id) return false
  const fp = vm.fingerprint && typeof vm.fingerprint === 'object' ? vm.fingerprint : {}
  const same =
    fp.hostname === computer.hostname &&
    String(fp.guest_machine_id || '')
      .trim()
      .toLowerCase() === computer.guest_machine_id
  if (same) return false
  vm.fingerprint = {
    ...fp,
    hostname: computer.hostname,
    guest_machine_id: computer.guest_machine_id,
  }
  const vmPath = path.join(projectRoot, 'vms', `${vm.id}.json`)
  if (!fs.existsSync(vmPath)) return true
  const disk = JSON.parse(fs.readFileSync(vmPath, 'utf8'))
  disk.fingerprint = {
    ...(disk.fingerprint && typeof disk.fingerprint === 'object' ? disk.fingerprint : {}),
    hostname: computer.hostname,
    guest_machine_id: computer.guest_machine_id,
  }
  disk.updated_at = new Date().toISOString()
  atomicWriteJson(vmPath, disk, { mode: 0o600 })
  return true
}

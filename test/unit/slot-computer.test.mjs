import '../fixtures/kin-computer-test-env.mjs'
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { RFC4122_UUID_RE } from '../../src/lib/identity/rfc4122-uuid.mjs'
import {
  DEVICE_ID_RE,
  HOSTNAME_RE,
  isPlaceholderHostname,
  MACHINE_ID_RE,
} from '../../src/lib/identity/workstation-fingerprint.mjs'
import { assignComputerFingerprint, ensureSlotComputer } from '../../src/lib/identity/slot-computer.mjs'

test('missing kin-computer binary throws computer_service_missing', () => {
  const prev = process.env.KIN_COMPUTER_BIN
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-computer-missing-'))
  try {
    process.env.KIN_COMPUTER_BIN = path.join(root, 'no-such-kin-computer-bin')
    const vm = { id: 'vm-missing-bin', kernel: 'ubuntu-24.04', runtime: { type: 'docker' } }
    assert.throws(
      () => ensureSlotComputer(root, vm),
      (err) => err?.code === 'computer_service_missing',
    )
  } finally {
    if (prev == null) delete process.env.KIN_COMPUTER_BIN
    else process.env.KIN_COMPUTER_BIN = prev
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('kvm fingerprint with empty uuid is repaired in place with RFC4122 writeback', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-computer-bad-uuid-'))
  const vm = { id: 'vm-bad-uuid', kernel: 'ubuntu-24.04', runtime: { type: 'kvm' } }
  const dir = path.join(root, 'vms', vm.id, 'kvm', 'fingerprint')
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(
    path.join(dir, 'identity.json'),
    `${JSON.stringify({ hostname: 'wks1234567890123', machine_id: 'a'.repeat(32), uuid: '' }, null, 2)}\n`,
  )
  fs.writeFileSync(path.join(dir, 'qemu-smbios.args'), '-smbios\ntype=1,manufacturer=KinStub,product=Test\n')
  const fixed = ensureSlotComputer(root, vm)
  assert.equal(fixed.created, false)
  const ident = JSON.parse(fs.readFileSync(path.join(fixed.dir, 'identity.json'), 'utf8'))
  assert.match(String(ident.uuid || ''), RFC4122_UUID_RE)
  const args = fs.readFileSync(path.join(fixed.dir, 'qemu-smbios.args'), 'utf8')
  assert.match(args, new RegExp(`-uuid\\s*\\n${ident.uuid}`, 'm'))
  assert.match(args, new RegExp(`uuid=${ident.uuid}`))
  fs.rmSync(root, { recursive: true, force: true })
})

test('kin-computer empty uuid after create is coerced before acceptance', () => {
  const prev = process.env.KIN_COMPUTER_STUB_EMPTY_UUID
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-computer-empty-create-'))
  try {
    process.env.KIN_COMPUTER_STUB_EMPTY_UUID = '1'
    const vm = { id: 'vm-empty-create', kernel: 'ubuntu-24.04', runtime: { type: 'kvm' } }
    const first = ensureSlotComputer(root, vm)
    assert.equal(first.created, true)
    const ident = JSON.parse(fs.readFileSync(path.join(first.dir, 'identity.json'), 'utf8'))
    assert.match(String(ident.uuid || ''), RFC4122_UUID_RE)
    const args = fs.readFileSync(path.join(first.dir, 'qemu-smbios.args'), 'utf8')
    assert.doesNotMatch(args, /-uuid\s*\n\s*\n/)
    assert.match(args, new RegExp(`uuid=${ident.uuid}`))
  } finally {
    if (prev == null) delete process.env.KIN_COMPUTER_STUB_EMPTY_UUID
    else process.env.KIN_COMPUTER_STUB_EMPTY_UUID = prev
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('linux computer is written once and device_id stays 64-bit', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-computer-linux-'))
  const vm = { id: 'vm-linux-1', kernel: 'ubuntu-24.04', runtime: { type: 'kvm' } }
  const first = ensureSlotComputer(root, vm)
  const second = ensureSlotComputer(root, vm)
  assert.equal(first.created, true)
  assert.equal(second.created, false)
  assert.equal(second.hostname, first.hostname)
  assert.equal(second.guest_machine_id, first.guest_machine_id)
  assert.match(first.hostname, HOSTNAME_RE)
  assert.doesNotMatch(first.hostname, /^[a-z]+-[0-9a-f]{4}$/)
  assert.match(first.guest_machine_id, MACHINE_ID_RE)
  assert.equal(fs.existsSync(path.join(first.dir, 'qemu-smbios.args')), true)
  const pack = assignComputerFingerprint(root, vm, {
    taken: { hostname: new Set(), device_id: new Set(), guest_machine_id: new Set() },
  })
  // A legitimate DMI-derived name is kept; only a placeholder or a taken name is replaced.
  assert.equal(pack.hostname, first.hostname)
  assert.notEqual(pack.guest_machine_id, first.guest_machine_id)
  assert.match(pack.device_id, DEVICE_ID_RE)
  const ident = JSON.parse(fs.readFileSync(path.join(first.dir, 'identity.json'), 'utf8'))
  const uuid = String(ident.uuid || '')
    .replace(/-/g, '')
    .toLowerCase()
  assert.notEqual(pack.device_id, uuid)
  fs.rmSync(root, { recursive: true, force: true })
})

test('fresh generation mints a new identity for a reused vm id', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-computer-fresh-'))
  const taken = { hostname: new Set(), device_id: new Set(), guest_machine_id: new Set() }
  try {
    const first = assignComputerFingerprint(
      root,
      { id: 'vm-03', kernel: 'ubuntu-24.04', runtime: { type: 'kvm' } },
      { taken },
    )
    // DELETE removes vms/<id>/ entirely, then nextNumericIndex hands vm-03 back out.
    fs.rmSync(path.join(root, 'vms', 'vm-03'), { recursive: true, force: true })
    const second = assignComputerFingerprint(
      root,
      { id: 'vm-03', kernel: 'ubuntu-24.04', runtime: { type: 'kvm' } },
      { taken },
    )
    assert.match(first.guest_machine_id, MACHINE_ID_RE)
    assert.match(second.guest_machine_id, MACHINE_ID_RE)
    assert.notEqual(second.guest_machine_id, first.guest_machine_id)
    const ident = JSON.parse(
      fs.readFileSync(path.join(root, 'vms', 'vm-03', 'kvm', 'fingerprint', 'identity.json'), 'utf8'),
    )
    assert.equal(String(ident.machine_id).toLowerCase(), second.guest_machine_id)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('fresh generation mints a new docker machine-id and MAC for a reused vm id', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-computer-fresh-docker-'))
  const taken = { hostname: new Set(), device_id: new Set(), guest_machine_id: new Set() }
  try {
    const vm = { id: 'vm-03', kernel: 'ubuntu-24.04', runtime: { type: 'docker' } }
    const first = assignComputerFingerprint(root, vm, { taken })
    fs.rmSync(path.join(root, 'vms', 'vm-03'), { recursive: true, force: true })
    const second = assignComputerFingerprint(root, vm, { taken })
    assert.notEqual(second.guest_machine_id, first.guest_machine_id)
    // The persona MAC came from the same vm-id seed before the fix.
    const mac = (id) =>
      fs.readFileSync(path.join(root, 'vms', 'vm-03', 'kvm', 'fingerprint', 'system', 'hardware', 'mac'), 'utf8').trim()
    assert.match(mac(), /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/)
    assert.notEqual(mac(), '')
    const mid = fs
      .readFileSync(path.join(root, 'vms', 'vm-03', 'kvm', 'fingerprint', 'system', 'etc', 'machine-id'), 'utf8')
      .trim()
    assert.equal(mid, second.guest_machine_id)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('placeholder DMI hostname is rejected and repaired in place', () => {
  const prev = process.env.KIN_COMPUTER_STUB_PLACEHOLDER_HOST
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-computer-placeholder-'))
  try {
    process.env.KIN_COMPUTER_STUB_PLACEHOLDER_HOST = '1'
    const kvm = { id: 'vm-03', kernel: 'ubuntu-24.04', runtime: { type: 'kvm' } }
    const first = ensureSlotComputer(root, kvm)
    const placeholder = 'system-product-name-b985d8'
    assert.notEqual(first.hostname, placeholder)
    assert.doesNotMatch(first.hostname, /^system-product-name/)
    assert.match(first.hostname, /^ubuntu-[0-9a-f]{4}$/)
    const ident = JSON.parse(fs.readFileSync(path.join(first.dir, 'identity.json'), 'utf8'))
    assert.equal(ident.hostname, first.hostname)

    const docker = { id: 'vm-04', kernel: 'ubuntu-24.04', runtime: { type: 'docker' } }
    const container = ensureSlotComputer(root, docker)
    assert.match(container.hostname, /^ubuntu-[0-9a-f]{4}$/)
    assert.equal(
      fs.readFileSync(path.join(container.dir, 'system', 'etc', 'hostname'), 'utf8').trim(),
      container.hostname,
    )
  } finally {
    if (prev == null) delete process.env.KIN_COMPUTER_STUB_PLACEHOLDER_HOST
    else process.env.KIN_COMPUTER_STUB_PLACEHOLDER_HOST = prev
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('an existing placeholder identity is repaired on the next ensure', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-computer-repair-'))
  try {
    const vm = { id: 'vm-07', kernel: 'ubuntu-24.04', runtime: { type: 'kvm' } }
    const dir = path.join(root, 'vms', 'vm-07', 'kvm', 'fingerprint')
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(
      path.join(dir, 'identity.json'),
      `${JSON.stringify(
        {
          hostname: 'system-product-name-b985d8',
          machine_id: 'a'.repeat(32),
          uuid: '11111111-2222-3333-4444-555555555555',
        },
        null,
        2,
      )}\n`,
    )
    fs.writeFileSync(
      path.join(dir, 'qemu-smbios.args'),
      '-smbios\ntype=1,manufacturer=ASUS,product=System Product Name\n',
    )
    const healed = ensureSlotComputer(root, vm)
    assert.equal(healed.created, false)
    assert.match(healed.hostname, /^ubuntu-[0-9a-f]{4}$/)
    // The machine-id is an existing identity and must not rotate on a repair.
    assert.equal(healed.guest_machine_id, 'a'.repeat(32))
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'identity.json'), 'utf8')).hostname, healed.hostname)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('placeholder detection rejects DMI defaults but keeps real machine names', () => {
  for (const value of [
    'system-product-name-b985d8',
    'system-product-name',
    'System Product Name',
    'to-be-filled-by-o-e-m',
    'Default string',
    'Not Specified',
    'unknown-abcd',
  ]) {
    assert.equal(isPlaceholderHostname(value), true, value)
  }
  for (const value of ['macbookpro11-4-20bd08', 'ubuntu-a3f1', 'wks1234567890123', 'kin-07']) {
    assert.equal(isPlaceholderHostname(value), false, value)
  }
})

test('container computer prepare is stable and exposes mac plus dmi', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-computer-os-'))
  const vm = { id: 'vm-os-1', kernel: 'ubuntu-24.04', runtime: { type: 'docker' } }
  const first = ensureSlotComputer(root, vm)
  const second = ensureSlotComputer(root, vm)
  assert.equal(first.created, true)
  assert.equal(second.created, false)
  assert.equal(second.hostname, first.hostname)
  assert.match(first.hostname, HOSTNAME_RE)
  assert.doesNotMatch(first.hostname, /^[a-z]+-[0-9a-f]{4}$/)
  assert.match(first.guest_machine_id, MACHINE_ID_RE)
  assert.match(first.mac, /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/)
  assert.equal(fs.statSync(path.join(first.dir, 'system', 'dmi', 'id')).isDirectory(), true)
  assert.equal(
    fs
      .readFileSync(path.join(first.dir, 'system', 'hardware', 'mac'), 'utf8')
      .trim()
      .toLowerCase(),
    first.mac,
  )
  fs.rmSync(root, { recursive: true, force: true })
})

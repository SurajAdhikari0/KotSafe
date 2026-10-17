import { describe, expect, it } from 'vitest'
import {
  canUseDesktopCapability,
  desktopCapabilitiesFor,
} from '../src/desktop/accessPolicy'

describe('desktop access policy', () => {
  it('denies every protected feature until a session exists', () => {
    expect(desktopCapabilitiesFor('loading')).toEqual([])
    expect(desktopCapabilitiesFor('signed_out')).toEqual([])
  })

  it('limits guest sessions to hosting an exit node', () => {
    expect(desktopCapabilitiesFor('guest')).toEqual(['guest_exit_node'])
    expect(canUseDesktopCapability('guest', 'guest_exit_node')).toBe(true)
    expect(canUseDesktopCapability('guest', 'client_mode')).toBe(false)
    expect(canUseDesktopCapability('guest', 'security_settings')).toBe(false)
    expect(canUseDesktopCapability('guest', 'mesh_pairing')).toBe(false)
    expect(canUseDesktopCapability('guest', 'cloud_sync')).toBe(false)
  })

  it('unlocks the full desktop workspace only for verified sessions', () => {
    expect(desktopCapabilitiesFor('authenticated')).toEqual([
      'guest_exit_node',
      'client_mode',
      'security_settings',
      'mesh_pairing',
      'cloud_sync',
    ])
  })
})

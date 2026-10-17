/**
 * Desktop access policy.
 *
 * This is deliberately a deny-by-default policy. The desktop host must apply
 * the same policy before it starts or configures any privileged service; UI
 * visibility alone is never an authorization boundary.
 */
export type DesktopAccessMode = 'loading' | 'signed_out' | 'guest' | 'authenticated';

export type DesktopCapability =
  | 'guest_exit_node'
  | 'client_mode'
  | 'security_settings'
  | 'mesh_pairing'
  | 'cloud_sync';

const capabilitiesByMode: Record<DesktopAccessMode, ReadonlySet<DesktopCapability>> = {
  loading: new Set(),
  signed_out: new Set(),
  guest: new Set(['guest_exit_node']),
  authenticated: new Set([
    'guest_exit_node',
    'client_mode',
    'security_settings',
    'mesh_pairing',
    'cloud_sync',
  ]),
};

export function desktopCapabilitiesFor(accessMode: DesktopAccessMode): readonly DesktopCapability[] {
  return [...capabilitiesByMode[accessMode]];
}

export function canUseDesktopCapability(
  accessMode: DesktopAccessMode,
  capability: DesktopCapability
): boolean {
  return capabilitiesByMode[accessMode].has(capability);
}

export function accessModeLabel(accessMode: DesktopAccessMode): string {
  switch (accessMode) {
    case 'guest':
      return 'Guest · Exit Node only';
    case 'authenticated':
      return 'Signed in';
    case 'signed_out':
      return 'Sign in required';
    default:
      return 'Checking secure session';
  }
}

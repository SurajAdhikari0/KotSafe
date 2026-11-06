import {LicenseApiResponse} from '../types/license';
import {auth} from '../firebase/firebaseConfig';
export async function sharedAccountLicense(action:'activate'|'verify'|'deactivate', key:string,deviceId:string):Promise<LicenseApiResponse> {
  const native=window.kotSafeDesktop;
  if(native?.licenseRequest) return native.licenseRequest(action,key,deviceId);
  const user=auth.currentUser;
  if(!user)throw new Error('Sign in before managing a KotSafe license.');
  const token=await user.getIdToken();
  const response=await fetch(`https://kotsafe.com/api/v1/license/${action}`,{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json',Authorization:`Bearer ${token}`,'X-KotSafe-Device-Id':deviceId},
    body:JSON.stringify({license_key:key,device_id:deviceId,device_name:'KotSafe web desktop',platform:'web',app_version:'2.0.0'}),signal:AbortSignal.timeout(10000)});
  const data=await response.json();
  if(!response.ok)throw new Error(data.message||'Account license request denied.');
  if(action==='deactivate')return {status:'invalid',plan:'freemium',expiresAt:null,seats:{used:0,max:0},signature:''};
  if(data.valid!==true)throw new Error('License verification was not successful.');
  // This is an online TLS observation, not an offline signed grant.
  return {status:'active',plan:data.tier==='ENTERPRISE'?'enterprise':'pro',expiresAt:data.expires_at?new Date(data.expires_at).toISOString():null,seats:{used:data.active_devices,max:data.max_devices},signature:'',serverTime:data.verified_at};
}

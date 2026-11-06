import {describe,it,expect,vi,afterEach} from 'vitest';
vi.mock('../src/firebase/firebaseConfig',()=>({auth:{currentUser:{getIdToken:vi.fn(async()=> 'fixture-id-token')}}}));
import {sharedAccountLicense} from '../src/api/sharedAccountLicense';
import {validateKeyFormat} from '../src/core/keyValidator';
describe('Shared Laravel license contract',()=>{
 afterEach(()=>{vi.unstubAllGlobals();});
 it('sends a verified identity to the fixed account origin and maps snake-case entitlement fields',async()=>{
  const send=vi.fn(async(_url:string,_options:{headers:{Authorization:string};body:string})=>({ok:true,json:async()=>({valid:true,tier:'ENTERPRISE',max_devices:25,active_devices:2,expires_at:0,verified_at:123})}));vi.stubGlobal('fetch',send);
  const value=await sharedAccountLicense('activate','KOT-ENT-ABCDE-FGHIJ-KLMNO','device-1234');
  expect(send.mock.calls[0][0]).toBe('https://kotsafe.com/api/v1/license/activate');
  const options=send.mock.calls[0][1];expect(options.headers.Authorization).toBe('Bearer fixture-id-token');expect(JSON.parse(options.body).license_key).toBe('KOT-ENT-ABCDE-FGHIJ-KLMNO');
  expect(value.seats).toEqual({used:2,max:25});expect(value.plan).toBe('enterprise');expect(value.signature).toBe('');
 });
 it('rejects backend denial rather than granting a plan',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>({ok:false,json:async()=>({message:'Device revoked'})})));
  await expect(sharedAccountLicense('verify','fixture','device-1234')).rejects.toThrow('Device revoked');
 });
 it('accepts the keys issued by the current admin portal',()=>{
  expect(validateKeyFormat('KOT-PRO-ABCDE-FGHIJ-KLMNO').isValid).toBe(true);
  expect(validateKeyFormat('KOT-LIFE-ABCDE-FGHIJ-KLMNO').isValid).toBe(true);
 });
});

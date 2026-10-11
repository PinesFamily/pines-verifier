// Browser-safe identity pin and session account confirmation. These values are
// public. The confirmation key comes from HPKE; the browser never receives K.
import {check,exact,unhex,digest,encode,lp} from './wire.mjs';
export const IDENTITY_PROTOCOL='pines-keyed-receipt-v2';
export async function checkIdentityBinding(value){
  exact(value,['generation','protocol','keyArn','wrappedSha256','configurationAuthority','configurationSha256']);
  check(value.generation==='v2'&&value.protocol===IDENTITY_PROTOCOL
    &&value.keyArn==='arn:aws:kms:ap-southeast-2:594194277294:key/3d63a788-0acf-42c1-b20c-1c3bdd9e2375','IDENTITY_CONFIGURATION');
  for(const field of ['wrappedSha256','configurationAuthority','configurationSha256'])unhex(value[field],32);
  const {configurationSha256,...body}=value;
  check(configurationSha256===await digest(encode(body)),'IDENTITY_CONFIGURATION');
  return value;
}
export const accountConfirmationMessage=(identity,provider,id,pseudonym)=>lp([
  IDENTITY_PROTOCOL,identity.configurationSha256,provider.host,provider.identitySourceVersion,id,pseudonym]);

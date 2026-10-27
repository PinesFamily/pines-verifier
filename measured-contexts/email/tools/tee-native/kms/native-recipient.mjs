// Only ciphertext, public SPKI and MACs cross this pipe. The native process
// retains K; it has no key export command. No shell, stderr capture or key env.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {parseRecipientEnvelope} from './recipient.mjs';
import {strictBase64} from './wrapped-store.mjs';
import {readFile} from 'node:fs/promises';
import {parseStatusMetrics} from '../runtime-metrics.mjs';

export const IDENTITY_BINARY='/app/bin/tee-identity';
export async function createNativeRecipient({binary=IDENTITY_BINARY}={}){
  const child=spawn(binary,[],{stdio:['pipe','pipe','ignore'],env:{LANG:'C',PATH:'/usr/bin:/bin'}});
  let pending,buffer='',dead=false,opened=false,chain=Promise.resolve();
  const fail=()=>{dead=true;pending?.reject(Error('KMS_NATIVE_REFUSED'));pending=undefined;
    if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');};
  child.once('error',fail);child.once('exit',fail);child.stdin.on('error',fail);
  child.stdout.on('data',chunk=>{
    buffer+=chunk.toString('utf8');
    if(buffer.length>2048){fail();child.kill();return;}
    const at=buffer.indexOf('\n');if(at<0)return;
    if(!pending||at!==buffer.length-1){fail();child.kill();return;}
    try {const reply=JSON.parse(buffer.slice(0,at));buffer='';
      assert(!reply.error,'KMS_NATIVE_REFUSED');const p=pending;pending=undefined;p.resolve(reply);
    }catch{fail();child.kill();}
  });
  function response(){
    assert(!dead&&!pending,'KMS_NATIVE_REFUSED');
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{fail();child.kill();},10000);
      pending={resolve:v=>{clearTimeout(timer);resolve(v);},reject:e=>{clearTimeout(timer);reject(e);}};
    });
  }
  function call(value){
    const run=chain.then(async()=>{const promise=response();child.stdin.write(JSON.stringify(value)+'\n');return promise;});
    chain=run.catch(()=>{});return run;
  }
  function destroy(){if(dead)return;dead=true;pending?.reject(Error('KMS_NATIVE_REFUSED'));pending=undefined;
    child.stdin.end(); // EOF runs native Drop and clears its locked page.
    const timer=setTimeout(()=>child.kill('SIGKILL'),1000);timer.unref();child.once('exit',()=>clearTimeout(timer));}
  try {
    const hello=await response();assert.deepEqual(Object.keys(hello),['publicKey'],'KMS_NATIVE_REFUSED');
    const publicKey=strictBase64(hello.publicKey,294);assert.equal(publicKey.length,294,'KMS_RECIPIENT_SPKI');
    return Object.freeze({publicKey,destroy,
      async openHandle(bytes){
        assert(!opened&&!dead,'KMS_NATIVE_REFUSED');opened=true;
        const e=parseRecipientEnvelope(bytes);
        const reply=await call({op:'open',encrypted_key:e.encryptedKey.toString('base64'),iv:e.iv.toString('base64'),ciphertext:e.ciphertext.toString('base64')});
        assert.deepEqual(reply,{ready:true},'KMS_NATIVE_REFUSED');
        return Object.freeze({get ready(){return opened&&!dead;},destroy,
          async metrics(){try{return parseStatusMetrics(await readFile(`/proc/${child.pid}/status`,'utf8'));}catch{return null;}},
          digest(bytes){assert(opened&&!dead&&bytes instanceof Uint8Array&&bytes.length<=65536,'KMS_KEY_NOT_READY');
            return call({op:'digest',message:Buffer.from(bytes).toString('base64')}).then(value=>{
              assert.deepEqual(Object.keys(value),['mac'],'KMS_NATIVE_REFUSED');
              const mac=strictBase64(value.mac,32);assert.equal(mac.length,32,'KMS_NATIVE_REFUSED');return mac;
            });}});
      }});
  }catch(error){destroy();throw error;}
}

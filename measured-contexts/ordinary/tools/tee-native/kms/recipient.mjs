// KMS Recipient CMS is opened only in the future enclave process. This module
// has no file/network/logging path. AWS format reference is linked in the runbook.
import assert from 'node:assert/strict';
const OID={enveloped:'2a864886f70d010703',data:'2a864886f70d010701',oaep:'2a864886f70d010107',
  sha256:'608648016503040201',mgf1:'2a864886f70d010108',pspecified:'2a864886f70d010109',aes256cbc:'60864801650304012a'};

function decodeBer(bytes){
  assert(Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<=8192,'KMS_RECIPIENT_LIMIT');
  let nodes=0;
  function read(start,end,depth){
    assert(++nodes<=96&&depth<=10&&start+2<=end,'KMS_RECIPIENT_ENCODING');
    let at=start;const tag=bytes[at++];assert((tag&31)!==31,'KMS_RECIPIENT_ENCODING');
    let n=bytes[at++],indefinite=n===128;
    if(n>128){const count=n&127;assert(count<=3&&at+count<=end,'KMS_RECIPIENT_ENCODING');n=0;
      for(let i=0;i<count;i++)n=n*256+bytes[at++];}
    const constructed=(tag&32)!==0;assert(!indefinite||constructed,'KMS_RECIPIENT_ENCODING');
    const limit=indefinite?end:at+n;assert(limit<=end,'KMS_RECIPIENT_ENCODING');
    const children=[];let next=limit,closed=!indefinite;
    if(constructed){
      let cursor=at;
      while(cursor<limit){
        if(indefinite&&bytes[cursor]===0&&bytes[cursor+1]===0){next=cursor+2;closed=true;break;}
        const item=read(cursor,limit,depth+1);children.push(item.node);cursor=item.next;
      }
      assert(closed&&(indefinite?next<=end:cursor===limit),'KMS_RECIPIENT_ENCODING');
    }
    return {node:{tag,value:bytes.subarray(at,indefinite?next-2:limit),children},next};
  }
  const root=read(0,bytes.length,0);assert.equal(root.next,bytes.length,'KMS_RECIPIENT_TRAILING_DATA');return root.node;
}
const children=(node,tag,count)=>{assert(node?.tag===tag&&node.children.length===count,'KMS_RECIPIENT_STRUCTURE');return node.children;};
const oid=(node,name)=>assert(node?.tag===6&&node.value.toString('hex')===OID[name],'KMS_RECIPIENT_ALGORITHM');
const version=node=>assert(node?.tag===2&&node.value.length===1&&node.value[0]===2,'KMS_RECIPIENT_VERSION');
function sha256Algorithm(node){
  assert(node?.tag===48&&(node.children.length===1||node.children.length===2),'KMS_RECIPIENT_ALGORITHM');oid(node.children[0],'sha256');
  if(node.children[1])assert(node.children[1].tag===5&&node.children[1].value.length===0,'KMS_RECIPIENT_ALGORITHM');
}
export function parseRecipientEnvelope(bytes){
  assert(bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=8192,'KMS_RECIPIENT_LIMIT');
  const [contentType,explicit]=children(decodeBer(Buffer.from(bytes)),48,2);oid(contentType,'enveloped');
  const [enveloped]=children(explicit,160,1),[ver,recipients,content]=children(enveloped,48,3);version(ver);
  const [recipient]=children(recipients,49,1),[rver,rid,keyAlgorithm,encryptedKey]=children(recipient,48,4);version(rver);
  assert(rid.tag===128&&rid.value.length>=1&&rid.value.length<=128,'KMS_RECIPIENT_ID');
  const [algorithm,params]=children(keyAlgorithm,48,2);oid(algorithm,'oaep');
  assert(params.tag===48&&(params.children.length===2||params.children.length===3),'KMS_RECIPIENT_ALGORITHM');
  sha256Algorithm(children(params.children[0],160,1)[0]);
  const [mgf]=children(params.children[1],161,1),[mgfOid,mgfHash]=children(mgf,48,2);oid(mgfOid,'mgf1');sha256Algorithm(mgfHash);
  if(params.children[2]){const [psource]=children(params.children[2],162,1),[po,empty]=children(psource,48,2);oid(po,'pspecified');
    assert(empty.tag===4&&empty.value.length===0,'KMS_RECIPIENT_LABEL');}
  assert(encryptedKey.tag===4&&encryptedKey.value.length===256,'KMS_RECIPIENT_RSA_SIZE');
  const [type,cipherAlgorithm,encrypted]=children(content,48,3);oid(type,'data');
  const [cipherOid,iv]=children(cipherAlgorithm,48,2);oid(cipherOid,'aes256cbc');assert(iv.tag===4&&iv.value.length===16,'KMS_RECIPIENT_IV');
  let ciphertext;
  if(encrypted.tag===128)ciphertext=Buffer.from(encrypted.value);
  else {assert(encrypted.tag===160&&encrypted.children.length>0&&encrypted.children.length<=8,'KMS_RECIPIENT_CONTENT');
    assert(encrypted.children.every(n=>n.tag===4),'KMS_RECIPIENT_CONTENT');ciphertext=Buffer.concat(encrypted.children.map(n=>n.value));}
  assert.equal(ciphertext.length,48,'KMS_RECIPIENT_KEY_LENGTH');
  return {encryptedKey:Buffer.from(encryptedKey.value),iv:Buffer.from(iv.value),ciphertext};
}

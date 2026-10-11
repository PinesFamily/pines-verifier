// Private qualification instrumentation. Values and body bytes never enter the
// returned object; this collector does not alter native disclosure policy.
export const MAX_REPLAY_METADATA_BYTES=65536;
export const REPLAY_METADATA_KEY='pines.qualification.replay-metadata.v1';
const FORMAT='pines-private-replay-metadata-v2';
// private-headers-gzip-v1 runs only: v2 plus value-free body framing, so the first real window records whether the
// egress honoured gzip and the header/encoded/decoded sizes (the trim report §7.1 and the client design record).
const FORMAT_PRIVATE='pines-private-replay-metadata-v3';
const ENCODINGS=['identity','gzip','other'];
const FRAMINGS=['content-length','chunked','none','invalid','incomplete'];
const MAX_CHUNKS=4096,MAX_DECODED_BYTES=1<<20;
const BODY_KEYS=['framing','contentEncoding','encodedBodyBytes','chunks'];
const TYPES=['empty','digits','quoted','jwt-shaped','ascii-token','ascii-text','opaque-bytes'];
const OUTCOMES=['response-observed','http-error','signed-in-shape','proof-failed','receipt-verified'];
// Closed, value-free milestones. These describe worker progress, not proof
// acceptance; only receipt validation may set receiptVerified.
const PROOF_STEPS=['response-observed','shape-accepted','reveal-started','reveal-completed','finish-started','receipt-verified'];
export const replayProofStepIndex=record=>PROOF_STEPS.indexOf(record.proofStep);
const COOKIE_ATTRIBUTES=['domain','path','expires','max-age','secure','httponly','samesite','partitioned','priority'];
const TOKEN=/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const number=(value,max=65536)=>Number.isSafeInteger(value)&&value>=0&&value<=max;
const ensure=value=>{if(!value)throw Error('REPLAY_METADATA_REFUSED');};
const trim=value=>value.replace(/^[ \t]+|[ \t]+$/g,'');
function type(value) {
  if(!value.length)return 'empty';
  if(/[^\x20-\x7e\t]/.test(value))return 'opaque-bytes';
  if(/^\d+$/.test(value))return 'digits';
  if(/^"[^"\r\n]*"$/.test(value))return 'quoted';
  if(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value))return 'jwt-shaped';
  return /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value)?'ascii-token':'ascii-text';
}
function cookieMetadata(value) {
  const parts=value.split(';'),pair=trim(parts.shift()),eq=pair.indexOf('=');
  const initial={name:null,valueBytes:0,valueType:'empty',shape:'malformed',attributes:[]};
  if(eq<1||!TOKEN.test(pair.slice(0,eq)))return initial;
  initial.name=pair.slice(0,eq);
  const secret=trim(pair.slice(eq+1));initial.valueBytes=secret.length;initial.valueType=type(secret);
  const octets=secret.startsWith('"')&&secret.endsWith('"')?secret.slice(1,-1):secret;
  let malformed=!/^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/.test(octets),ambiguous=parts.length>16;
  const names=new Set();
  for(const part of parts.slice(0,16)){
    const text=trim(part),split=text.indexOf('='),name=(split<0?text:text.slice(0,split)).toLowerCase();
    if(!TOKEN.test(name)){malformed=true;continue;}
    // A malformed '; SECRET' segment must not turn a private value into an
    // exported arbitrary attribute name. Unknown attributes stay unexported.
    if(!COOKIE_ATTRIBUTES.includes(name)){ambiguous=true;continue;}
    const hidden=split<0?'':trim(text.slice(split+1));
    if(['secure','httponly','partitioned'].includes(name)?split>=0:split<0||!hidden.length)malformed=true;
    if(names.has(name)||hidden.includes(',')&&name!=='expires')ambiguous=true;
    names.add(name);
    initial.attributes.push({name,hasValue:split>=0,valueBytes:hidden.length,valueType:type(hidden)});
  }
  initial.shape=malformed?'malformed':ambiguous?'ambiguous':'parsed';return initial;
}

export function collectReplayResponse(bytes) {
  ensure(bytes instanceof Uint8Array&&bytes.length<=65536);
  const http={status:null,responseBytes:bytes.length,headerBytes:0,headersComplete:false,cookieMetadataComplete:false};
  const headers=[];let end=-1;
  for(let i=0;i+3<Math.min(bytes.length,8192);i++)if(bytes[i]===13&&bytes[i+1]===10&&bytes[i+2]===13&&bytes[i+3]===10){end=i;break;}
  if(end<0)return {http,headers};
  http.headerBytes=end+4;
  const lines=String.fromCharCode(...bytes.subarray(0,end)).split('\r\n');
  const status=/^HTTP\/1\.1 ([1-5]\d{2}) [\x20-\x7e]{0,128}$/.exec(lines.shift()??'');
  if(!status)return {http,headers};http.status=Number(status[1]);
  if(lines.some(line=>!line||/^[ \t]|[\x00-\x08\x0a-\x1f\x7f]/.test(line)||line.indexOf(':')<1))return {http,headers};
  let cookies=0;http.headersComplete=lines.length<=64;http.cookieMetadataComplete=http.headersComplete;
  for(const line of lines.slice(0,64)){
    const split=line.indexOf(':'),name=line.slice(0,split).toLowerCase();
    if(!TOKEN.test(name)){http.headersComplete=false;http.cookieMetadataComplete=false;continue;}
    const hidden=trim(line.slice(split+1)),row={name,valueBytes:hidden.length,valueType:type(hidden)};
    if(name==='set-cookie'){
      cookies++;
      if(cookies<=16){row.cookie=cookieMetadata(hidden);if(row.cookie.shape!=='parsed')http.cookieMetadataComplete=false;}
      else http.cookieMetadataComplete=false;
    }
    headers.push(row);
  }
  return {http,headers};
}

// New campaigns retain only closed diagnostic categories. Inspect at most the
// first 8192 bytes even when a failed/oversized replay returned more bytes.
// This changes diagnostics only: proof transcript limits remain 8192/65536.
export function collectBoundedReplayDiagnostic(bytes,{transport='complete'}={}){
  ensure(bytes instanceof Uint8Array&&['complete','failed','unavailable'].includes(transport));
  const prefix=bytes.subarray(0,8192),collected=collectReplayResponse(prefix),http=collected.http;
  let contentType='absent',redirect=false;
  // Header values are used only to select fixed labels, and never retained.
  if(http.headersComplete){
    const header=new TextDecoder('latin1').decode(prefix.subarray(0,http.headerBytes));
    const types=[...header.matchAll(/^content-type:\s*([^\r\n]*)/gim)];
    if(types.length>1)contentType='ambiguous';
    else if(types.length){const media=types[0][1].split(';')[0].trim().toLowerCase();
      contentType=media==='application/json'?'json':media==='text/html'?'html':media.startsWith('text/')?'text':'other';}
    redirect=http.status>=300&&http.status<400;
  }
  return {headers:[],http:{...http,cookieMetadataComplete:false,responseBytes:Math.min(bytes.length,65536),
    observedResponseBytes:Math.min(bytes.length,16*1024*1024),responseLengthCapped:bytes.length>16*1024*1024,
    responseLimitExceeded:bytes.length>65536,contentType,redirect,
    transport:bytes.length>65536?'receive-limit':transport}};
}

// Body framing and encoding as closed labels and counts. Header values select a label and are never retained; the
// body view is returned only to measureDecodedBody below, inside this module, and never enters a record.
function bodyFraming(bytes,http){
  const result={framing:'incomplete',contentEncoding:'identity',encodedBodyBytes:null,chunks:0,body:null};
  if(!http.headersComplete)return result;
  const header=new TextDecoder('latin1').decode(bytes.subarray(0,Math.min(http.headerBytes,8192))).split('\r\n').slice(1);
  const values=name=>header.filter(line=>line.slice(0,line.indexOf(':')).toLowerCase()===name).map(line=>trim(line.slice(line.indexOf(':')+1)).toLowerCase());
  const encoding=values('content-encoding'),transfer=values('transfer-encoding'),length=values('content-length');
  result.contentEncoding=!encoding.length?'identity':encoding.length===1&&['gzip','identity'].includes(encoding[0])?encoding[0]:'other';
  // Only the inspected 8192-byte prefix is read, as for the headers; the body runs to the end only when it is whole.
  const whole=bytes.length<=8192,rest=bytes.subarray(http.headerBytes,8192);
  if(transfer.length){
    if(transfer.length!==1||transfer[0]!=='chunked'||length.length){result.framing='invalid';return result;}
    const parts=[];let at=0,size=0;
    for(;;){
      let end=-1;for(let i=at;i+1<rest.length;i++)if(rest[i]===13&&rest[i+1]===10){end=i;break;}
      if(end<0)return result;
      const line=String.fromCharCode(...rest.subarray(at,end));
      if(!/^[0-9a-fA-F]{1,6}$/.test(line)){result.framing='invalid';return result;}
      const chunk=parseInt(line,16);at=end+2;
      if(chunk===0){
        if(rest.length<at+2)return result;
        if(rest[at]!==13||rest[at+1]!==10){result.framing='invalid';return result;}
        break;
      }
      if(rest.length<at+chunk+2)return result;
      if(rest[at+chunk]!==13||rest[at+chunk+1]!==10){result.framing='invalid';return result;}
      if(++result.chunks>MAX_CHUNKS){result.framing='invalid';result.chunks=MAX_CHUNKS;return result;}
      parts.push(rest.subarray(at,at+chunk));size+=chunk;at+=chunk+2;
    }
    const body=new Uint8Array(size);let offset=0;for(const part of parts){body.set(part,offset);offset+=part.length;}
    Object.assign(result,{framing:'chunked',encodedBodyBytes:size,body});return result;
  }
  if(length.length){
    if(length.length!==1||!/^\d{1,7}$/.test(length[0])){result.framing='invalid';return result;}
    const size=Number(length[0]);if(rest.length<size)return result;
    Object.assign(result,{framing:'content-length',encodedBodyBytes:size,body:rest.slice(0,size)});return result;
  }
  // connection: close; the body runs to the end only when this prefix is the whole response.
  if(!whole)return result;
  Object.assign(result,{framing:'none',encodedBodyBytes:rest.length,body:rest.slice()});return result;
}

// The decoded size, or null: a gzip body is inflated with a cap and nothing else is kept. The worker passes the
// schema package's bounded decoder (D6, `gunzip`) and the schema's maxDecodedBodyBytes, so a size is recorded exactly
// when the proof's own decode accepts the body. Without one (this module stays import-free for the unbundled
// offscreen page) DecompressionStream sizes it.
export async function measureDecodedBody(bytes,{maxDecodedBytes=MAX_DECODED_BYTES,decode}={}){
  ensure(bytes instanceof Uint8Array&&number(maxDecodedBytes,MAX_DECODED_BYTES));
  const {http}=collectReplayResponse(bytes.subarray(0,8192));
  const framed=bodyFraming(bytes,http);
  try{
    if(!framed.body||framed.contentEncoding==='other')return null;
    if(framed.contentEncoding==='identity')return framed.encodedBodyBytes;
    if(decode){const decoded=decode(framed.body,maxDecodedBytes),size=decoded.length;decoded.fill(0);return size<=maxDecodedBytes?size:null;}
    if(typeof DecompressionStream!=='function')return null;
    const reader=new Blob([framed.body]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
    let total=0;
    for(;;){
      const {done,value}=await reader.read();
      if(done)return total;
      total+=value.length;value.fill(0);
      if(total>maxDecodedBytes){await reader.cancel().catch(()=>{});return null;}
    }
  }catch{return null;}
  finally{framed.body?.fill(0);}
}

// The one qualification package allowed to collect new runtime records. Rebound per
// operation by tools/tee-native/qualification/bind-normal-scope.py; tests import it.
export const QUALIFICATION_EXTENSION_VERSION='1.13.12';

export function metadataConfiguration(config) {
  const value=config?.qualificationResponseMetadata;
  if(!value)return null;
  ensure(value.version===1&&value.qualificationOnly===true&&value.extensionVersion===QUALIFICATION_EXTENSION_VERSION
    &&/^[a-f0-9]{40}$/.test(value.sourceRevision)&&/^[a-f0-9]{32}$/.test(value.operation)
    &&value.maxRecords===32&&value.maxBytes===262144&&config.extensionId==='lanmbpkmblcijblbllbikenpnceidmpj'
    &&config.origins?.length===1&&config.origins[0]===value.origin&&config.tee);
  const fixture=config.tee.fixture?.hardware===true;
  ensure(value.origin===(fixture?'http://localhost:5262':'http://localhost:5203')
    &&value.apiOrigin===(fixture?'http://localhost:8991':'http://localhost:8992')
    &&config.tee.api===value.apiOrigin+'/tee');
  if(value.receiver!==undefined)ensure(value.receiver===value.origin+'/qualification/replay-metadata'&&/^[a-f0-9]{64}$/.test(value.receiverToken));
  return value;
}

export function validateReplayMetadata(record) {
  ensure(exact(record,['format','captureId','runId','attemptId','operation','provider','observedAt','updatedAt','stage',
    'extensionVersion','sourceRevision','synthetic','attestedChannel','receiptVerified','signedInShapeAccepted','outcome','http','headers',
    ...(['1.4.6','1.4.7','1.4.8','1.4.9','1.5.0','1.5.1','1.5.2','1.5.3','1.5.4','1.5.5','1.5.6','1.5.7','1.5.8','1.6.6','1.7.0','1.8.9','1.9.0','1.9.1','1.9.2','1.9.3','1.10.0','1.12.0','1.12.1','1.12.2','1.12.3','1.12.4','1.12.5','1.12.6','1.12.7','1.12.8','1.12.9','1.12.10','1.13.8','1.13.9','1.13.10','1.13.11','1.13.12'].includes(record.extensionVersion)?['proofStep']:[])]));
  ensure([FORMAT,FORMAT_PRIVATE,'pines-private-replay-metadata-v1'].includes(record.format)&&[record.captureId,record.runId,record.attemptId].every(value=>typeof value==='string'&&UUID.test(value))
    &&/^[a-f0-9]{32}$/.test(record.operation)&&['chatgpt','claude','grok'].includes(record.provider)
    // Archived observations retain their original version. Runtime collection
    // and delivery apply a separate exact current-version/campaign binding.
    &&['1.4.3','1.4.4','1.4.5','1.4.6','1.4.7','1.4.8','1.4.9','1.5.0','1.5.1','1.5.2','1.5.3','1.5.4','1.5.5','1.5.6','1.5.7','1.5.8','1.6.6','1.7.0','1.8.9','1.9.0','1.9.1','1.9.2','1.9.3','1.10.0','1.12.0','1.12.1','1.12.2','1.12.3','1.12.4','1.12.5','1.12.6','1.12.7','1.12.8','1.12.9','1.12.10','1.13.8','1.13.9','1.13.10','1.13.11','1.13.12'].includes(record.extensionVersion)&&/^[a-f0-9]{40}$/.test(record.sourceRevision));
  ensure(number(record.observedAt,8640000000000000)&&number(record.updatedAt,8640000000000000)&&record.updatedAt>=record.observedAt
    &&number(record.stage,2)&&['synthetic','attestedChannel','receiptVerified','signedInShapeAccepted'].every(key=>typeof record[key]==='boolean')
    &&OUTCOMES.includes(record.outcome));
  ensure(record.attestedChannel===true&&(!record.receiptVerified||record.signedInShapeAccepted&&record.outcome==='receipt-verified'&&record.stage===2));
  if(['1.4.6','1.4.7','1.4.8','1.4.9','1.5.0','1.5.1','1.5.2','1.5.3','1.5.4','1.5.5','1.5.6','1.5.7','1.5.8','1.6.6','1.7.0','1.8.9','1.9.0','1.9.1','1.9.2','1.9.3','1.10.0','1.12.0','1.12.1','1.12.2','1.12.3','1.12.4','1.12.5','1.12.6','1.12.7','1.12.8','1.12.9','1.12.10','1.13.8','1.13.9','1.13.10','1.13.11','1.13.12'].includes(record.extensionVersion)){
    const step=replayProofStepIndex(record);ensure(step>=0);
    ensure(record.signedInShapeAccepted===(step>=1)&&record.receiptVerified===(step===5));
  }
  ensure(record.outcome==='response-observed'?record.stage===0&&!record.signedInShapeAccepted&&!record.receiptVerified
    :record.outcome==='signed-in-shape'?record.stage===1&&record.signedInShapeAccepted&&!record.receiptVerified
    :record.stage===2&&(record.outcome==='receipt-verified'?record.receiptVerified:!record.receiptVerified));
  const h=record.http;
  const body=record.format===FORMAT_PRIVATE,bounded=record.format===FORMAT||body;
  ensure(exact(h,['status','responseBytes','headerBytes','headersComplete','cookieMetadataComplete',
    ...(bounded?['observedResponseBytes','responseLengthCapped','responseLimitExceeded','contentType','redirect','transport']:[]),
    ...(body?[...BODY_KEYS,...(Object.hasOwn(h,'decodedBodyBytes')?['decodedBodyBytes']:[])]:[])])
    &&(h.status===null||Number.isInteger(h.status)&&h.status>=100&&h.status<=599)
    &&number(h.responseBytes)&&number(h.headerBytes,8192)&&h.headerBytes<=h.responseBytes
    &&typeof h.headersComplete==='boolean'&&typeof h.cookieMetadataComplete==='boolean'
    &&(!h.cookieMetadataComplete||h.headersComplete)&&Array.isArray(record.headers)&&record.headers.length<=64);
  if(bounded)ensure(record.headers.length===0&&h.cookieMetadataComplete===false&&number(h.observedResponseBytes,16*1024*1024)
    &&h.observedResponseBytes>=h.responseBytes&&h.responseBytes===Math.min(h.observedResponseBytes,65536)
    &&h.responseLimitExceeded===(h.observedResponseBytes>65536)&&typeof h.responseLengthCapped==='boolean'
    &&(!h.responseLengthCapped||h.observedResponseBytes===16*1024*1024)&&typeof h.redirect==='boolean'
    &&['absent','ambiguous','json','html','text','other'].includes(h.contentType)
    &&['complete','failed','unavailable','receive-limit'].includes(h.transport)
    &&(!h.responseLimitExceeded||h.transport==='receive-limit'));
  if(body)ensure(FRAMINGS.includes(h.framing)&&ENCODINGS.includes(h.contentEncoding)&&number(h.chunks,MAX_CHUNKS)
    // A bounded prefix can contain complete data chunks before the next chunk
    // is cut off. Keep that observation without claiming a complete body.
    &&(h.chunks===0||['chunked','invalid','incomplete'].includes(h.framing))
    &&(['content-length','chunked','none'].includes(h.framing)?number(h.encodedBodyBytes)&&h.encodedBodyBytes<=h.responseBytes-h.headerBytes
      :h.encodedBodyBytes===null)
    &&(!Object.hasOwn(h,'decodedBodyBytes')||number(h.decodedBodyBytes,MAX_DECODED_BYTES)&&h.encodedBodyBytes!==null&&h.contentEncoding!=='other'
      &&(h.contentEncoding==='gzip'||h.decodedBodyBytes===h.encodedBodyBytes)));
  const typed=row=>number(row.valueBytes)&&TYPES.includes(row.valueType);
  let cookies=0;
  for(const row of record.headers){
    ensure(exact(row,['name','valueBytes','valueType',...(Object.hasOwn(row,'cookie')?['cookie']:[])])
      &&typeof row.name==='string'&&TOKEN.test(row.name)&&row.name===row.name.toLowerCase()&&typed(row));
    if(Object.hasOwn(row,'cookie')){
      const cookie=row.cookie;cookies++;
      ensure(row.name==='set-cookie'&&cookies<=16&&exact(cookie,['name','valueBytes','valueType','shape','attributes'])
        &&(cookie.name===null||typeof cookie.name==='string'&&TOKEN.test(cookie.name))&&typed(cookie)
        &&['parsed','ambiguous','malformed'].includes(cookie.shape)&&Array.isArray(cookie.attributes)&&cookie.attributes.length<=16);
      for(const attr of cookie.attributes)ensure(exact(attr,['name','hasValue','valueBytes','valueType'])
        &&COOKIE_ATTRIBUTES.includes(attr.name)
        &&typeof attr.hasValue==='boolean'&&typed(attr));
      ensure(!h.cookieMetadataComplete||cookie.shape==='parsed');
    }
    ensure(!h.cookieMetadataComplete||row.name!=='set-cookie'||Object.hasOwn(row,'cookie'));
  }
  ensure(!record.signedInShapeAccepted||h.status===200);
  ensure(record.outcome!=='http-error'||h.status!==200&&!record.signedInShapeAccepted);
  ensure(new TextEncoder().encode(JSON.stringify(record)).length<=MAX_REPLAY_METADATA_BYTES);return record;
}

export function newReplayMetadata({config,runId,attemptId,provider,bytes,transport='complete',now=Date.now(),privateHeaders=false,decodedBodyBytes}) {
  const enabled=metadataConfiguration(config);if(!enabled)return null;
  const diagnostic=collectBoundedReplayDiagnostic(bytes,{transport});
  if(privateHeaders){
    // Labels and counts only; the framed body view is dropped here.
    const {body,...framed}=bodyFraming(bytes,diagnostic.http);body?.fill(0);
    Object.assign(diagnostic.http,framed,Number.isSafeInteger(decodedBodyBytes)&&framed.encodedBodyBytes!==null
      &&framed.contentEncoding!=='other'?{decodedBodyBytes}:{});
  }
  return validateReplayMetadata({format:privateHeaders?FORMAT_PRIVATE:FORMAT,captureId:crypto.randomUUID(),runId,attemptId,operation:enabled.operation,provider,
    observedAt:now,updatedAt:now,stage:0,extensionVersion:enabled.extensionVersion,sourceRevision:enabled.sourceRevision,
    synthetic:config.tee.fixture?.hardware===true,attestedChannel:true,receiptVerified:false,signedInShapeAccepted:false,
    outcome:'response-observed',proofStep:'response-observed',...diagnostic});
}

export function updateReplayMetadata(record,outcome,now=Date.now()) {
  if(!record)return null;
  const shape=record.signedInShapeAccepted||outcome==='signed-in-shape'||outcome==='receipt-verified';
  return validateReplayMetadata({...record,outcome,updatedAt:Math.max(now,record.updatedAt),
    ...(['1.4.6','1.4.7','1.4.8','1.4.9','1.5.0','1.5.1','1.5.2','1.5.3','1.5.4','1.5.5','1.5.6','1.5.7','1.5.8','1.6.6','1.7.0','1.8.9','1.9.0','1.9.1','1.9.2','1.9.3','1.10.0','1.12.0','1.12.1','1.12.2','1.12.3','1.12.4','1.12.5','1.12.6','1.12.7','1.12.8','1.12.9','1.12.10','1.13.8','1.13.9','1.13.10','1.13.11','1.13.12'].includes(record.extensionVersion)?{proofStep:outcome==='receipt-verified'?'receipt-verified':
      outcome==='signed-in-shape'?'shape-accepted':record.proofStep}:{}),
    stage:outcome==='signed-in-shape'?1:2,signedInShapeAccepted:shape,receiptVerified:outcome==='receipt-verified'});
}

export function advanceReplayProofStep(record,proofStep,now=Date.now()){
  if(!record)return null;
  validateReplayMetadata(record);
  ensure(['1.4.6','1.4.7','1.4.8','1.4.9','1.5.0','1.5.1','1.5.2','1.5.3','1.5.4','1.5.5','1.5.6','1.5.7','1.5.8','1.6.6','1.7.0','1.8.9','1.9.0','1.9.1','1.9.2','1.9.3','1.10.0','1.12.0','1.12.1','1.12.2','1.12.3','1.12.4','1.12.5','1.12.6','1.12.7','1.12.8','1.12.9','1.12.10','1.13.8','1.13.9','1.13.10','1.13.11','1.13.12'].includes(record.extensionVersion)&&record.stage===1
    &&['reveal-started','reveal-completed','finish-started'].includes(proofStep)
    &&PROOF_STEPS.indexOf(proofStep)===replayProofStepIndex(record)+1);
  return validateReplayMetadata({...record,proofStep,updatedAt:Math.max(now,record.updatedAt)});
}

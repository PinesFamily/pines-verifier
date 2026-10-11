import {metadataConfiguration,validateReplayMetadata,REPLAY_METADATA_KEY,replayProofStepIndex} from './replay-metadata.mjs';
import {metadataPersistenceFailureCode} from './qualification-metadata-channel.mjs';
const ensure=value=>{if(!value)throw Error('REPLAY_METADATA_REFUSED');};
const encoded=value=>new TextEncoder().encode(JSON.stringify(value)).length;
const configuration=config=>{try{const value=metadataConfiguration(config);ensure(value);return value;}catch{throw Error('REPLAY_METADATA_CONFIG_REFUSED');}};
const history=records=>{try{ensure(Array.isArray(records)&&records.length<=32);records.forEach(validateReplayMetadata);}catch{throw Error('REPLAY_METADATA_HISTORY_REFUSED');}};

export function metadataRecords(previous,record,config) {
  const enabled=configuration(config);
  validateReplayMetadata(record);
  if(!(record.operation===enabled.operation&&record.extensionVersion===enabled.extensionVersion
    &&record.sourceRevision===enabled.sourceRevision&&record.synthetic===(config.tee.fixture?.hardware===true)))throw Error('REPLAY_METADATA_SCOPE_REFUSED');
  history(previous);
  const existing=previous.find(row=>row.captureId===record.captureId);
  if(existing){
    ensure(['runId','attemptId','operation','provider','observedAt','sourceRevision','extensionVersion','synthetic'].every(key=>existing[key]===record[key]));
    if(existing.stage>record.stage||existing.stage===record.stage&&existing.updatedAt>record.updatedAt)return previous;
    if(replayProofStepIndex(existing)>replayProofStepIndex(record))return previous;
    ensure(!existing.receiptVerified||record.receiptVerified);
  }
  const result=[...previous.filter(row=>row.captureId!==record.captureId),record];
  while(result.length>enabled.maxRecords||encoded(result)>enabled.maxBytes)result.shift();
  ensure(result.some(row=>row.captureId===record.captureId));return result;
}

export function qualificationMetadataStore(browser,config,{fetcher=fetch}={}) {
  let writes=Promise.resolve(),deliveryTask=null;
  const pendingKey=REPLAY_METADATA_KEY+'.pending';
  const serial=work=>{const current=writes.catch(()=>{}).then(work);writes=current;return current;};
  const validPending=value=>Array.isArray(value)&&value.length<=32&&value.every(row=>row&&typeof row.captureId==='string'
    &&Number.isInteger(row.tries)&&row.tries>=0&&row.tries<=8);
  async function read(){
    let saved;
    try{saved=await browser.storage.local.get([REPLAY_METADATA_KEY,pendingKey]);}catch{throw Error('REPLAY_METADATA_READ_FAILED');}
    const records=saved[REPLAY_METADATA_KEY]??[],pending=saved[pendingKey]??[];
    history(records);if(!validPending(pending))throw Error('REPLAY_METADATA_HISTORY_REFUSED');
    return {records,pending};
  }
  const store=record=>serial(async()=>{
    configuration(config);
    const saved=await read();let records;
    try{records=metadataRecords(saved.records,record,config);}catch(error){throw Error(metadataPersistenceFailureCode(error?.message)??'REPLAY_METADATA_PERSIST_FAILED');}
    const pending=[...saved.pending.filter(row=>row.captureId!==record.captureId&&records.some(value=>value.captureId===row.captureId)),{captureId:record.captureId,tries:0}];
    try{await browser.storage.local.set({[REPLAY_METADATA_KEY]:records,[pendingKey]:pending});}catch{throw Error('REPLAY_METADATA_WRITE_FAILED');}
    // This acknowledgment certifies the local commit only. Network delivery is
    // separate, so a receiver outage cannot delay or falsify durable capture.
    return {stored:true,delivered:false,pending:pending.length};
  });
  store.flush=()=>{
    if(deliveryTask)return deliveryTask;
    deliveryTask=(async()=>{
      const enabled=configuration(config);
      const saved=await serial(read),item=saved.pending[0];
      if(!item)return {stored:true,delivered:false,pending:0};
      const current=saved.records.find(row=>row.captureId===item.captureId);
      let delivered=false;
      const eligible=current&&enabled.receiver&&current.operation===enabled.operation&&current.sourceRevision===enabled.sourceRevision;
      if(eligible){
        try{
          const response=await fetcher(enabled.receiver,{method:'POST',credentials:'omit',redirect:'error',cache:'no-store',
            headers:{'content-type':'application/json',authorization:'Bearer '+enabled.receiverToken},
            body:JSON.stringify(current),signal:AbortSignal.timeout(1200)});
          delivered=response.ok===true;
        }catch{}
      }
      return serial(async()=>{
        const latest=await read(),record=latest.records.find(row=>row.captureId===item.captureId);
        // A later worker stage committed during fetch owns its own retry. An
        // older network acknowledgment must never remove that pending stage.
        if(JSON.stringify(current)!==JSON.stringify(record))return {stored:true,delivered,pending:latest.pending.length};
        const remaining=latest.pending.filter(row=>row.captureId!==item.captureId);
        if(!delivered&&eligible&&item.tries<7&&Date.now()-current.updatedAt<15*60000)remaining.push({...item,tries:item.tries+1});
        await browser.storage.local.set({[pendingKey]:remaining});
        return {stored:true,delivered,pending:remaining.length};
      });
    })().finally(()=>{deliveryTask=null;});
    return deliveryTask;
  };
  return store;
}

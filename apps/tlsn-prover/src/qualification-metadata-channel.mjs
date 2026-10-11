// Worker-local acknowledgment channel. Only a completed background storage
// commit can satisfy it; timeout does not count as metadata qualification.
// Closed stages only: never forward the underlying exception or record.
export const REPLAY_METADATA_PERSISTENCE_FAILURES=Object.freeze([
  'REPLAY_METADATA_PERSIST_FAILED', 'REPLAY_METADATA_JOB_REFUSED',
  'REPLAY_METADATA_CONFIG_REFUSED', 'REPLAY_METADATA_READ_FAILED',
  'REPLAY_METADATA_HISTORY_REFUSED', 'REPLAY_METADATA_SCOPE_REFUSED',
  'REPLAY_METADATA_WRITE_FAILED', 'REPLAY_METADATA_RETRY_FAILED',
  'REPLAY_METADATA_BRIDGE_FAILED', 'REPLAY_METADATA_BRIDGE_REFUSED',
]);
export const metadataPersistenceFailureCode=value=>REPLAY_METADATA_PERSISTENCE_FAILURES.includes(value)?value:null;
export const REPLAY_METADATA_FAILURES=Object.freeze([
  'REPLAY_METADATA_UNAVAILABLE', 'REPLAY_METADATA_BUILD_FAILED',
  'REPLAY_METADATA_RECORD_REFUSED', ...REPLAY_METADATA_PERSISTENCE_FAILURES,
  'REPLAY_METADATA_ACK_REFUSED', 'REPLAY_METADATA_ACK_TIMEOUT', 'REPLAY_METADATA_SEND_FAILED',
]);
export const replayMetadataFailureCode=value=>REPLAY_METADATA_FAILURES.includes(value)?value:null;
export function metadataChannel({send,timeoutMs=2000,timers=globalThis}) {
  const replies=new Map();
  return {
    acknowledge(data){
      const current=replies.get(data.requestId);
      if(current&&current.runId===data.runId)current.finish(data.ok===true,
        data.error==='REPLAY_METADATA_RECORD_REFUSED'?data.error:metadataPersistenceFailureCode(data.error)??'REPLAY_METADATA_ACK_REFUSED');
    },
    persist(runId,record){
      if(!record)return Promise.resolve();
      const requestId=crypto.randomUUID();
      return new Promise((resolve,reject)=>{
        const finish=(ok,code)=>{timers.clearTimeout(timer);replies.delete(requestId);ok?resolve():reject(Error(code));};
        const timer=timers.setTimeout(()=>finish(false,'REPLAY_METADATA_ACK_TIMEOUT'),timeoutMs);
        replies.set(requestId,{runId,finish});
        try{send({type:'replay-metadata',runId,requestId,record});}catch{finish(false,'REPLAY_METADATA_SEND_FAILED');}
      });
    },
  };
}

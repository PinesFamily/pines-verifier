// Private, bounded control-health counters only. No identifiers, raw errors,
// stdout/stderr, transcript bytes or provider values enter this module.
export const DIAGNOSTIC_COUNT_MAX=1_000_000;
// The measured verifier's closed failure stages (its only failure detail).
export const NATIVE_STAGE_CODES=Object.freeze(['NATIVE_CHANNEL','NATIVE_COMMIT_PROPOSAL','NATIVE_ORIGIN_CONNECT',
  'NATIVE_COMMIT_ACCEPT','NATIVE_PROXY_RUN','NATIVE_TRANSCRIPT_LIMIT','NATIVE_PROVE_PROPOSAL','NATIVE_PROPOSAL_POLICY',
  'NATIVE_PROXY_FORWARD','NATIVE_PROXY_FORWARD_BROKEN_PIPE','NATIVE_PROXY_FORWARD_RESET','NATIVE_PROXY_FORWARD_EOF',
  'NATIVE_PROXY_FORWARD_TIMEOUT','NATIVE_PROXY_FORWARD_POLICY','NATIVE_PROXY_FORWARD_IO','NATIVE_PROXY_IO',
  'NATIVE_PROXY_TRANSCRIPT','NATIVE_PROXY_PREPROCESS','NATIVE_PROXY_TAG_SETUP','NATIVE_PROXY_TAG_EXECUTION','NATIVE_PROXY_TAG_VERIFY',
  'NATIVE_PROVE_ACCEPT','NATIVE_DRIVER_CLOSE','NATIVE_OUTPUT_POLICY']);
export const nativeStageCode=code=>NATIVE_STAGE_CODES.includes(code)?code:'PROTOCOL_REFUSED';
export const NATIVE_REFUSAL_CODES=Object.freeze(['PROTOCOL_REFUSED','IPC_PARSE_REFUSED','EVALUATION_REFUSED',
  'NATIVE_START_TIMEOUT','IPC_LIMIT','NATIVE_START','NATIVE_EXIT','NATIVE_STOPPED','UNKNOWN_NATIVE_REFUSAL',...NATIVE_STAGE_CODES]);
export const SESSION_CLOSE_CAUSES=Object.freeze(['CONNECTION_REFUSED','CLIENT_SOCKET_CLOSED','CLIENT_SOCKET_ERROR',
  'HANDSHAKE_DEADLINE','SESSION_DEADLINE','INPUT_FRAME_REFUSED','INPUT_QUEUE_LIMIT','OUTPUT_QUEUE_LIMIT',
  'OUTPUT_SEND_REFUSED','INPUT_PROTOCOL_REFUSED','NATIVE_PREPARATION_REFUSED','NATIVE_START_REFUSED','NATIVE_SOCKET_ERROR','NATIVE_FRAME_REFUSED',
  'NATIVE_REFUSED','NATIVE_RESULT_ERROR','CLIENT_CANCELLED','OPERATOR_CANCELLED','SERVICE_SHUTDOWN',
  'RECEIPT_PREPARATION_REFUSED','COMPLETED','UNKNOWN_CLOSE']);
const counters=keys=>Object.fromEntries(keys.map(key=>[key,0]));
const increment=(counts,key)=>{counts[key]=Math.min(DIAGNOSTIC_COUNT_MAX,counts[key]+1);};
export function sessionDiagnostics(){
  const closed=counters(SESSION_CLOSE_CAUSES),primary=counters(NATIVE_REFUSAL_CODES),secondary=counters(NATIVE_REFUSAL_CODES);
  return {
    begin(){
      let firstClose,refusalRecorded=false;
      return {
        close(cause){
          if(firstClose!==undefined)return;
          firstClose=SESSION_CLOSE_CAUSES.includes(cause)?cause:'UNKNOWN_CLOSE';increment(closed,firstClose);
        },
        nativeRefusal(code){
          if(refusalRecorded)return;refusalRecorded=true;
          const key=NATIVE_REFUSAL_CODES.includes(code)?code:'UNKNOWN_NATIVE_REFUSAL';
          increment(firstClose===undefined?primary:secondary,key);
        },
      };
    },
    snapshot(){return {version:1,closed:{...closed},nativeRefusals:{primary:{...primary},secondary:{...secondary}}};},
  };
}

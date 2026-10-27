// HTTPS connector for the deferred keyed-identity KMS call. The parent carries
// bytes over the measured runtime's fixed `enclave-kms-egress` pipe; the TLS
// handshake, certificate chain and hostname check all happen in this process,
// so a parent that re-resolves or reroutes the endpoint still reads nothing and
// cannot substitute a certificate. No AWS request is made on import.
import assert from 'node:assert/strict';
import {Agent} from 'node:https';
import {connect as netConnect} from 'node:net';
import {connect as tlsConnect} from 'node:tls';
import {kmsEndpoint} from './transport.mjs';

// Measured loopback addresses of the runtime's KMS bridges (main.rs).
export const KMS_BRIDGE=Object.freeze({host:'127.0.0.1',port:18020});
export const KMS_HANDOFF_BRIDGE=Object.freeze({host:'127.0.0.1',port:18021});
export const LOCAL_TEST_LABEL='local-synthetic-test';

export function checkedBridge(bridge){
  assert(bridge&&typeof bridge==='object'&&bridge.host==='127.0.0.1'
    &&[KMS_BRIDGE.port,KMS_HANDOFF_BRIDGE.port].includes(bridge.port),'KMS_BRIDGE_SCOPE');
  return Object.freeze({host:bridge.host,port:bridge.port});
}
/**
 * `substitute` exists only for local tests without a vsock device or AWS: it must
 * carry the explicit label, and it is the only way to add a trust anchor or a
 * different socket factory. Production callers pass neither.
 */
export function createKmsVsockAgent({bridge=KMS_BRIDGE,substitute}={}){
  const route=checkedBridge(bridge);
  assert(substitute===undefined||(substitute&&substitute.label===LOCAL_TEST_LABEL),'KMS_BRIDGE_SUBSTITUTE_LABEL');
  const connectRaw=substitute?.connect??(()=>netConnect({host:route.host,port:route.port,allowHalfOpen:false}));
  const startTls=substitute?.tls??tlsConnect;
  const agent=new Agent({keepAlive:false,maxSockets:1,maxFreeSockets:0});
  agent.createConnection=options=>{
    // The signed request fixes the endpoint; a changed host, port or relaxed
    // verification never reaches a socket.
    const host=options.servername??options.host??options.hostname;
    assert.equal(host,kmsEndpoint.hostname,'KMS_TRANSPORT_HOST');
    assert(options.host===undefined||options.host===kmsEndpoint.hostname,'KMS_TRANSPORT_HOST');
    assert(options.port===undefined||Number(options.port)===kmsEndpoint.port,'KMS_TRANSPORT_HOST');
    assert.equal(options.rejectUnauthorized,true,'KMS_TLS_VERIFICATION_REQUIRED');
    const socket=connectRaw();
    return startTls({socket,host:kmsEndpoint.hostname,servername:kmsEndpoint.hostname,
      rejectUnauthorized:true,minVersion:'TLSv1.2',ALPNProtocols:['http/1.1'],
      ...(substitute?.anchors?{ca:substitute.anchors}:{})});
  };
  return agent;
}

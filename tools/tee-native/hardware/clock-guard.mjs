import {check} from '../wire.mjs';
export function clockGuard(wall,monotonic) {
  const initialWall=wall(),initialMono=monotonic();let failed=false;
  return timestamp=>{
    const now=wall(),mono=monotonic();
    failed ||= !Number.isSafeInteger(timestamp) || Math.abs(timestamp-now)>2000
      || Math.abs((now-initialWall)-(mono-initialMono))>2000 || mono<initialMono;
    check(!failed,'CLOCK_PROVENANCE');
  };
}

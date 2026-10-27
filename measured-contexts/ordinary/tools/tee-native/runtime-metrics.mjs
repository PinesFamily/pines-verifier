// Bounded numeric diagnostics sampled INSIDE the measured enclave. Never return
// proc lines, process identifiers, names, argv, maps, environment or exceptions.
import {readFile} from 'node:fs/promises';
import {MAX_PROOF_SLOTS} from './capacity-policy.mjs';
const CPU_FIELDS=['user','nice','system','idle','iowait','irq','softirq','steal','guest','guestNice'];
const integer=value=>Number.isSafeInteger(value)&&value>=0?value:null;
export function parseStatusMetrics(text){
  const kib=key=>{const value=text.match(new RegExp('^'+key+':\\s+(\\d+) kB$','m'))?.[1];return value===undefined?null:integer(Number(value)*1024);};
  const threads=text.match(/^Threads:\s+(\d+)$/m)?.[1];
  return {rssBytes:kib('VmRSS'),peakRssBytes:kib('VmHWM'),virtualBytes:kib('VmSize'),peakVirtualBytes:kib('VmPeak'),
    threads:threads===undefined?null:integer(Number(threads))};
}
export function parseProcessCpuMetrics(text){
  // comm is parenthesized but may itself contain spaces, parentheses or newlines.
  // Parse only fields after its final delimiter; never retain or export comm.
  const end=text.lastIndexOf(')'),fields=text.slice(end+2).trim().split(/\s+/);
  if(!/^\d+ \(/.test(text)||end<3||text[end+1]!==' '||fields.length<20||!/^[A-Za-z]$/.test(fields[0]))return null;
  const values=[fields[11],fields[12],fields[19]];
  if(!values.every(value=>/^\d+$/.test(value)&&integer(Number(value))!==null))return null;
  return {userTicks:Number(values[0]),systemTicks:Number(values[1]),startTicks:Number(values[2])};
}
export function parseSystemMetrics(memory,cpu){
  const kib=key=>{const value=memory.match(new RegExp('^'+key+':\\s+(\\d+) kB$','m'))?.[1];return value===undefined?null:integer(Number(value)*1024);};
  const fields=cpu.match(/^cpu\s+([\d ]+)$/m)?.[1].trim().split(/\s+/).map(Number);
  return {totalBytes:kib('MemTotal'),availableBytes:kib('MemAvailable'),freeBytes:kib('MemFree'),
    cpuTicks:fields?.length===10&&fields.every(n=>integer(n)!==null)?Object.fromEntries(CPU_FIELDS.map((name,i)=>[name,fields[i]])):null};
}

export function startRuntimeMetrics({nativePids,queues,identityMetrics=async()=>null,intervalMs=250,read=readFile,clock=Date.now,
  usage=()=>({cpu:process.cpuUsage(),memory:process.memoryUsage()})}){
  if(!Number.isSafeInteger(intervalMs)||intervalMs<100||intervalMs>10000)throw Error('METRIC_INTERVAL');
  let sample=null,pending,stopped=false,peakRss=null,peakVirtual=null;
  const previousCpu=new Map();let cumulativeUser=0,cumulativeSystem=0,cpuSampledProcesses=0;
  let processPeakVirtual=null,processPeakRss=null,completedReports=0;
  function observePeaks(value){
    if(!value||!['peakVirtualBytes','peakRssBytes'].every(k=>Number.isSafeInteger(value[k])&&value[k]>0&&value[k]<=4096*1024**2))return;
    processPeakVirtual=Math.max(processPeakVirtual??0,value.peakVirtualBytes);processPeakRss=Math.max(processPeakRss??0,value.peakRssBytes);
  }
  async function numericRead(path,max){
    try{const value=await read(path,'utf8');return Buffer.byteLength(value)<=max?value:null;}catch{return null;}
  }
  async function collect(){
    const started=clock(),pids=[...nativePids()];
    const pidsValid=pids.length<=MAX_PROOF_SLOTS&&pids.every(pid=>Number.isSafeInteger(pid)&&pid>0);
    const [memory,cpu,own,...children]=await Promise.all([
      numericRead('/proc/meminfo',32768),numericRead('/proc/stat',1048576),numericRead('/proc/self/status',32768),
      ...(pidsValid?pids.map(pid=>Promise.all([numericRead(`/proc/${pid}/status`,32768),numericRead(`/proc/${pid}/stat`,32768)])):[])]);
    const parsed=children.map(([status,cpu])=>({status:status===null?null:parseStatusMetrics(status),cpu:cpu===null?null:parseProcessCpuMetrics(cpu)}));
    for(const child of parsed)observePeaks(child.status);
    const failures=parsed.filter(value=>value.status===null||value.cpu===null||Object.values(value.status).some(n=>n===null)).length;
    const complete=pidsValid&&failures===0;
    const sum=field=>complete?integer(parsed.reduce((total,value)=>total+value.status[field],0)):null;
    const cpuSum=field=>complete?integer(parsed.reduce((total,value)=>total+value.cpu[field],0)):null;
    if(pidsValid){
      for(let i=0;i<pids.length;i++){
        const current=parsed[i].cpu;if(current===null)continue;
        const previous=previousCpu.get(pids[i]),same=previous?.startTicks===current.startTicks;
        if(same&&(current.userTicks<previous.userTicks||current.systemTicks<previous.systemTicks))continue;
        cumulativeUser=cumulativeUser===null?null:integer(cumulativeUser+current.userTicks-(same?previous.userTicks:0));
        cumulativeSystem=cumulativeSystem===null?null:integer(cumulativeSystem+current.systemTicks-(same?previous.systemTicks:0));
        if(!same)cpuSampledProcesses++;previousCpu.set(pids[i],current);
      }
      for(const pid of previousCpu.keys())if(!pids.includes(pid))previousCpu.delete(pid);
    }
    const rss=sum('rssBytes'),virtual=sum('virtualBytes');
    if(rss!==null)peakRss=Math.max(peakRss??0,rss);if(virtual!==null)peakVirtual=Math.max(peakVirtual??0,virtual);
    let node=null;
    try{const value=usage();node={cpuUserMicros:integer(value.cpu.user),cpuSystemMicros:integer(value.cpu.system),
      rssBytes:integer(value.memory.rss),heapUsedBytes:integer(value.memory.heapUsed),heapTotalBytes:integer(value.memory.heapTotal),
      externalBytes:integer(value.memory.external),arrayBufferBytes:integer(value.memory.arrayBuffers),
      ...(own===null?{peakRssBytes:null,virtualBytes:null,peakVirtualBytes:null,threads:null}:parseStatusMetrics(own))};}catch{}
    const observedQueues=queues(),queue={};
    for(const field of ['inputBytes','outputBytes','inputMessages','outputMessages','protocolBufferedBytes','ciphertextBufferedBytes'])
      queue[field]=integer(observedQueues[field]);
    sample=Object.freeze({version:1,sampledAtMs:integer(started),sampleDurationMs:integer(clock()-started),intervalMs,
      system:memory===null||cpu===null?null:parseSystemMetrics(memory,cpu),node,identity:await identityMetrics(),
      native:{liveProcesses:pids.length,readFailures:failures,available:complete?1:0,rssBytes:rss,virtualBytes:virtual,
        peakRssBytes:sum('peakRssBytes'),peakVirtualBytes:sum('peakVirtualBytes'),threads:sum('threads'),
        sampledPeakAggregateRssBytes:peakRss,sampledPeakAggregateVirtualBytes:peakVirtual,
        cpuUserTicks:cpuSum('userTicks'),cpuSystemTicks:cpuSum('systemTicks'),cpuSampledProcesses,
        sampledCumulativeUserTicks:cumulativeUser,sampledCumulativeSystemTicks:cumulativeSystem,
        maxProcessPeakVirtualBytes:processPeakVirtual,maxProcessPeakRssBytes:processPeakRss,completedReports},queues:queue});
  }
  const tick=()=>{
    if(stopped||pending)return pending;
    pending=collect().catch(()=>{sample=null;}).finally(()=>{pending=undefined;});return pending;
  };
  const timer=setInterval(()=>{void tick();},intervalMs);timer.unref();void tick();
  return {snapshot:()=>sample,sample:tick,recordPeaks(value){observePeaks(value);completedReports++;},
    stop:async()=>{stopped=true;clearInterval(timer);await pending;}};
}

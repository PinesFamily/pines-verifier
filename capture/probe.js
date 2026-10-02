const output = document.getElementById('status');
const error = document.getElementById('error');
async function send(type) {
  const value = await chrome.runtime.sendMessage({type}).catch(() => ({ok: false, error: 'CAPTURE_UNAVAILABLE'}));
  if (type !== 'status') error.textContent = value?.ok ? '' : (value?.error ?? 'CAPTURE_UNAVAILABLE');
  output.textContent = JSON.stringify(value ?? {ok: false, error: 'CAPTURE_UNAVAILABLE'}, null, 2);
}
document.getElementById('start').onclick = () => void send('start');
document.getElementById('cancel').onclick = () => void send('cancel');
setInterval(() => void send('status'), 500);
void send('status');

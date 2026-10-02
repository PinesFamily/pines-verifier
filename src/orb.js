// The site's loading orb (thinking-orbs, MIT, as the Pines profile and dialogs show it) without React. The ink is the
// dark theme's; a reader who asked for less motion gets one still frame, and the orb pauses while its page is hidden
// or it is off screen. build.mjs bundles this with the library's engine into dist/orb.js, its notice on top.
import {MODE_FRAMES, paintFrame, resolvePreset} from 'thinking-orbs/engine';

/** Draws an orb into `host` (a 20 px `connecting` one by default) and returns the function that stops it. */
export function mountOrb(host, {size = 20, state = 'connecting', label = 'Working'} = {}) {
  const canvas = document.createElement('canvas');
  const dpr = Math.min(2, devicePixelRatio || 1);
  canvas.width = canvas.height = Math.round(size * dpr);
  canvas.style.cssText = `display:block;width:${size}px;height:${size}px`;
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', label);
  host.replaceChildren(canvas);
  const ctx = canvas.getContext('2d');
  const {mode, speed, opts} = resolvePreset(state, size);
  const frameOf = MODE_FRAMES[mode];
  const draw = seconds => {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, size, size);
    paintFrame(ctx, frameOf(size, seconds, opts), true);
  };
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) {
    draw(0.6);
    return () => host.replaceChildren();
  }
  let raf = 0, visible = true;
  const loop = () => { draw(performance.now() / 1000 * speed); raf = requestAnimationFrame(loop); };
  const run = () => {
    cancelAnimationFrame(raf); raf = 0;
    if (visible && document.visibilityState !== 'hidden') raf = requestAnimationFrame(loop);
  };
  draw(performance.now() / 1000 * speed);
  const io = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; run(); });
  io.observe(canvas);
  document.addEventListener('visibilitychange', run);
  return () => {
    cancelAnimationFrame(raf); io.disconnect();
    document.removeEventListener('visibilitychange', run);
    host.replaceChildren();
  };
}

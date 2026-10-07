const environmentButtons = document.querySelectorAll<HTMLButtonElement>('[data-environment]');
const environmentOutput = document.getElementById('example-environment');
const environmentStatus = document.getElementById('example-status');
for (const button of environmentButtons) {
  button.addEventListener('click', () => {
    const environment = button.dataset.environment;
    if (!environment || !environmentOutput || !environmentStatus) return;
    environmentOutput.textContent = environment;
    environmentStatus.textContent = `Illustrative ${environment} output. No credential is resolved.`;
    for (const other of environmentButtons) other.setAttribute('aria-pressed', String(other === button));
  });
}

const motionToggle = document.querySelector<HTMLButtonElement>('#motion-toggle');
const motionLabel = motionToggle?.querySelector('span:last-child');
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
let userPaused = false;
function updateMotion() {
  const paused = userPaused || reducedMotion.matches || document.hidden;
  document.documentElement.dataset.motion = paused ? 'paused' : 'running';
  if (!motionToggle || !motionLabel) return;
  motionToggle.hidden = reducedMotion.matches;
  motionToggle.setAttribute('aria-pressed', String(userPaused));
  motionLabel.textContent = userPaused ? 'Resume animations' : 'Pause animations';
}
motionToggle?.addEventListener('click', () => { userPaused = !userPaused; updateMotion(); });
reducedMotion.addEventListener('change', updateMotion);
document.addEventListener('visibilitychange', updateMotion);
updateMotion();
const scenes = document.querySelectorAll<HTMLElement>('.motion-scene');
if ('IntersectionObserver' in window) {
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) (entry.target as HTMLElement).dataset.visible = String(entry.isIntersecting);
  }, { threshold: 0.15 });
  for (const scene of scenes) observer.observe(scene);
} else {
  for (const scene of scenes) scene.dataset.visible = 'true';
}

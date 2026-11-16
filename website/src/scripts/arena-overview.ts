// The original field note remains addressable from historical inbound links.
const legacy = new Set(['agents', 'traps', 'questions', 'sandbox', 'controls', 'day', 'results', 'boundary', 'lessons', 'runs']);
const redirectLegacy = () => {
  if (legacy.has(location.hash.slice(1))) location.replace(`/arena/field-notes/poisoned-readme/${location.hash}`);
};
redirectLegacy();
window.addEventListener('hashchange', redirectLegacy);

const replay = document.querySelector<HTMLElement>('[data-replay]');
if (replay) {
  const stages = Array.from(replay.querySelectorAll<HTMLElement>('[data-stage]'));
  const steps = Array.from(replay.querySelectorAll<HTMLButtonElement>('[data-step]'));
  const play = replay.querySelector<HTMLButtonElement>('[data-play]')!;
  const previous = replay.querySelector<HTMLButtonElement>('[data-previous]')!;
  const next = replay.querySelector<HTMLButtonElement>('[data-next]')!;
  const position = replay.querySelector<HTMLElement>('[data-replay-position]')!;
  const labels = ['A useful task', 'An unwanted upload', 'Borrowed credentials', 'Useful work survives'];
  let current = 3;
  let timer: ReturnType<typeof setInterval> | undefined;
  const stop = () => { clearInterval(timer); timer = undefined; play.innerHTML = '<span aria-hidden="true">▷</span> Play walkthrough'; play.setAttribute('aria-pressed', 'false'); };
  const show = (index: number) => {
    current = Math.max(0, Math.min(index, stages.length - 1));
    stages.forEach((stage, i) => { stage.hidden = i !== current; });
    steps.forEach((step, i) => { step.setAttribute('aria-pressed', String(i === current)); });
    previous.disabled = current === 0;
    next.disabled = current === stages.length - 1;
    position.textContent = `0${current + 1} / 04 · ${labels[current]}`;
  };
  replay.querySelectorAll<HTMLElement>('.replay-steps, .replay-controls, [data-play]').forEach(el => { el.hidden = false; });
  show(current);
  steps.forEach((step, i) => step.addEventListener('click', () => { stop(); show(i); }));
  previous.addEventListener('click', () => { stop(); show(current - 1); });
  next.addEventListener('click', () => { stop(); show(current + 1); });
  play.setAttribute('aria-pressed', 'false');
  play.addEventListener('click', () => {
    if (timer) { stop(); return; }
    show(0);
    play.innerHTML = '<span aria-hidden="true">Ⅱ</span> Pause walkthrough';
    play.setAttribute('aria-pressed', 'true');
    timer = setInterval(() => { show(current + 1); if (current === stages.length - 1) stop(); }, 7000);
  });
  replay.querySelector('.replay-panels')!.addEventListener('focusin', stop);
  document.addEventListener('visibilitychange', () => { if (document.hidden) stop(); });
  window.addEventListener('pagehide', stop);
}

const browser = document.querySelector<HTMLElement>('[data-studies]');
if (browser) {
  const filters = Array.from(browser.querySelectorAll<HTMLButtonElement>('[data-filter]'));
  const search = browser.querySelector<HTMLInputElement>('[data-search]')!;
  const rows = Array.from(browser.querySelectorAll<HTMLElement>('[data-study]'));
  const count = browser.querySelector<HTMLElement>('[data-study-count]')!;
  const empty = browser.querySelector<HTMLElement>('[data-empty]')!;
  let active = 'all';
  const update = () => {
    const terms = search.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    let shown = 0;
    rows.forEach(row => {
      const matches = (active === 'all' || row.dataset.status === active) && terms.every(term => row.dataset.searchText?.includes(term));
      row.hidden = !matches;
      if (matches) shown++;
    });
    filters.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.filter === active)));
    count.textContent = `${shown} of ${rows.length} field notes`;
    empty.hidden = shown !== 0;
  };
  browser.querySelector<HTMLElement>('.study-tools')!.hidden = false;
  count.hidden = false;
  filters.forEach(button => button.addEventListener('click', () => { active = button.dataset.filter!; update(); }));
  search.addEventListener('input', update);
  browser.querySelector<HTMLButtonElement>('[data-reset]')!.addEventListener('click', () => { active = 'all'; search.value = ''; update(); search.focus(); });
  update();
}

const sections = Array.from(document.querySelectorAll<HTMLElement>('.arena-overview section[id]'));
const navLinks = Array.from(document.querySelectorAll<HTMLAnchorElement>('.arena-section-nav a'));
if ('IntersectionObserver' in window) {
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) if (entry.isIntersecting) {
      navLinks.forEach(link => { if (link.hash === `#${entry.target.id}`) link.setAttribute('aria-current', 'location'); else link.removeAttribute('aria-current'); });
    }
  }, { rootMargin: '-10% 0px -60% 0px', threshold: 0 });
  sections.forEach(section => observer.observe(section));
}

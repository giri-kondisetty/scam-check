import { analyze } from './analyze.js';
import { createBlocklist } from './blocklist.js';

const VERDICTS = {
  scam: { title: 'Likely a scam', summary: 'Strong warning signs match known scams.' },
  careful: { title: 'Be careful', summary: 'Some warning signs were found.' },
  none: { title: 'No warning signs found', summary: 'Nothing here matched a known warning sign.' },
};

const ICONS = {
  scam: '<svg viewBox="0 0 24 24"><path d="M8 3h8l5 5v8l-5 5H8l-5-5V8z"/><path d="M9 9l6 6M15 9l-6 6"/></svg>',
  careful: '<svg viewBox="0 0 24 24"><path d="M12 3.5L21.5 20h-19z"/><path d="M12 10v4.5M12 17.2v.3"/></svg>',
  none: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8 12h8"/></svg>',
};

const EXAMPLES = {
  parcel: 'USPS: Your package is on hold because of an unpaid customs fee. Pay within 24 hours at usps.com-track-package[.]info or it will be returned.',
  bank: 'Chase alert: a sign-in from a new device was blocked. Your account will be locked. Reply with the 6-digit code we just sent you to confirm it is you.',
  boss: "Hi, it's your manager. I'm in a meeting and can't talk. Can you buy 5 Apple gift cards and send me the codes? Don't tell anyone, I'll pay you back today.",
  invest: "Hi, I'm Anna, my analyst runs a private trading group with guaranteed returns of 5% daily. Message me on WhatsApp to join, withdrawals are instant.",
  job: 'We found your resume. Part-time job, no experience needed, daily pay $300. Buy your own laptop and software from our vendor first, we refund you on day one.',
  normal: 'Hey, are we still on for dinner on Friday at 7? Let me know.',
};

const blocklist = createBlocklist(async (key) => {
  const response = await fetch(`data/blocklist/${key}.txt`);
  if (!response.ok) throw new Error(`list ${key} returned ${response.status}`);
  return response.text();
});

const $ = (id) => document.getElementById(id);

function show(result) {
  const section = $('result');
  if (result.verdict === 'empty') {
    section.hidden = true;
    return;
  }
  const verdict = VERDICTS[result.verdict];
  section.hidden = false;
  section.dataset.verdict = result.verdict;
  $('icon').innerHTML = ICONS[result.verdict];
  $('verdict').textContent = verdict.title;
  $('summary').textContent = verdict.summary;
  $('next').textContent = result.nextStep;
  $('why').hidden = result.reasons.length === 0;

  const list = $('reasons');
  list.replaceChildren();
  for (const reason of result.reasons) {
    const item = document.createElement('li');
    const title = document.createElement('strong');
    const tag = document.createElement('span');
    tag.className = reason.weight >= 3 ? 'tag strong' : 'tag';
    tag.textContent = reason.weight >= 3 ? 'Strong' : 'Sign';
    title.append(tag, reason.title);
    const detail = document.createElement('span');
    detail.className = 'detail';
    detail.textContent = reason.detail;
    item.append(title, detail);
    if (reason.link) {
      const link = document.createElement('code');
      link.textContent = reason.link;
      item.append(link);
    }
    list.append(item);
  }
  $('coverage').textContent =
    result.linkCount && !result.blocklistChecked
      ? 'The list of reported scam sites could not be loaded, so links were not checked against it.'
      : '';
  section.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

async function run() {
  $('check').disabled = true;
  try {
    show(await analyze($('message').value, { blocklist }));
  } finally {
    $('check').disabled = false;
  }
}

$('form').addEventListener('submit', (event) => {
  event.preventDefault();
  run();
});

$('message').addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    run();
  }
});

$('clear').addEventListener('click', () => {
  $('message').value = '';
  $('result').hidden = true;
  $('message').focus();
});

for (const button of document.querySelectorAll('[data-example]')) {
  button.addEventListener('click', () => {
    $('message').value = EXAMPLES[button.dataset.example];
    run();
  });
}

fetch('data/blocklist/meta.json')
  .then((response) => (response.ok ? response.json() : Promise.reject()))
  .then((meta) => {
    const date = new Date(meta.built).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
    $('listinfo').textContent = `Reported scam sites: ${meta.hosts.toLocaleString()}, list updated ${date}.`;
  })
  .catch(() => {});

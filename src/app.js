import { analyze } from './analyze.js';
import { createBlocklist } from './blocklist.js';

const VERDICTS = {
  scam: 'Likely a scam',
  careful: 'Be careful',
  none: 'No warning signs found',
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
  section.hidden = false;
  section.dataset.verdict = result.verdict;
  $('verdict').textContent = VERDICTS[result.verdict];
  $('next').textContent = result.nextStep;
  const list = $('reasons');
  list.replaceChildren();
  for (const reason of result.reasons) {
    const item = document.createElement('li');
    const title = document.createElement('strong');
    title.textContent = reason.title;
    const detail = document.createElement('span');
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
}

$('check').addEventListener('click', async () => {
  $('check').disabled = true;
  try {
    show(await analyze($('message').value, { blocklist }));
  } finally {
    $('check').disabled = false;
  }
});

$('clear').addEventListener('click', () => {
  $('message').value = '';
  $('result').hidden = true;
  $('message').focus();
});

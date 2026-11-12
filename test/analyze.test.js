import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../site/src/analyze.js';
import { extractLinks, linkSignals, registrableDomain } from '../site/src/links.js';
import { createBlocklist, hostHash } from '../site/src/blocklist.js';

const ids = (result) => result.reasons.map((r) => r.id);

test('a bank message asking for a code through a look-alike link is a scam', async () => {
  const result = await analyze(
    'Your Chase account has been suspended. Verify within 24 hours and enter your security code at http://chase-secure-login.example-verify.com/login',
  );
  assert.equal(result.verdict, 'scam');
  assert.ok(ids(result).includes('asks-for-code'));
  assert.ok(ids(result).includes('impersonates-brand'));
  assert.ok(ids(result).includes('urgency'));
});

test('a gift card request is a scam on its own', async () => {
  const result = await analyze('Hi, I am in a meeting. Can you buy 3 Apple gift cards and send me the codes?');
  assert.equal(result.verdict, 'scam');
  assert.match(result.nextStep, /Do not pay/);
});

test('an ordinary message has no warning signs and does not claim to be safe', async () => {
  const result = await analyze('Hey, are we still on for dinner on Friday at 7? Let me know.');
  assert.equal(result.verdict, 'none');
  assert.equal(result.reasons.length, 0);
  assert.match(result.nextStep, /not proof/);
});

test('a real brand link is not flagged as imitation', () => {
  const [link] = extractLinks('Track it at https://www.amazon.co.uk/orders');
  assert.equal(link.host, 'amazon.co.uk');
  assert.deepEqual(linkSignals(link), []);
});

test('a brand name on someone else\'s domain is flagged', () => {
  const [link] = extractLinks('https://paypal.com.account-review.xyz/verify');
  assert.ok(linkSignals(link).some((s) => s.id === 'impersonates-brand'));
});

test('a single mild sign asks for care, not a scam verdict', async () => {
  const result = await analyze('Reminder: your parcel will be returned. Reply urgently to rearrange delivery.');
  assert.equal(result.verdict, 'careful');
});

test('registrable domain handles two-level suffixes', () => {
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('login.example.com'), 'example.com');
});

test('a link whose site or parent site is on the reported list is a scam', async () => {
  const hash = await hostHash('bad-site.test');
  const blocklist = createBlocklist(async (key) => (key === hash.slice(0, 2) ? `${hash}\n` : ''));
  const result = await analyze('see https://login.bad-site.test/a', { blocklist });
  assert.equal(result.verdict, 'scam');
  assert.equal(result.reasons[0].id, 'reported');
  assert.equal(result.blocklistChecked, true);
});

test('a failed list download does not break the check and is reported as unchecked', async () => {
  const blocklist = createBlocklist(async () => {
    throw new Error('offline');
  });
  const result = await analyze('see https://example.org/a', { blocklist });
  assert.equal(result.verdict, 'none');
  assert.equal(result.blocklistChecked, false);
});

test('empty input gives no verdict', async () => {
  assert.equal((await analyze('   ')).verdict, 'empty');
});

test('words joined by a full stop are not read as links', async () => {
  const result = await analyze('I ordered it from amazon.Thanks for checking.See you at the meeting.Can you call?');
  assert.equal(result.linkCount, 0);
  assert.equal(result.verdict, 'none');
});

test('a bare site name with a common ending is read as a link', () => {
  assert.equal(extractLinks('go to paypa1-secure.xyz/login now')[0].host, 'paypa1-secure.xyz');
});

test('a link written with [.] is read as the real address', async () => {
  const result = await analyze('usps.com-track-package[.]info');
  assert.equal(result.verdict, 'scam');
  assert.ok(result.reasons.some((r) => r.id === 'impersonates-brand'));
  assert.match(result.reasons[0].detail, /com-track-package\.info/);
});

test('hxxp and [dot] forms are read as links too', () => {
  assert.equal(extractLinks('hxxps://paypal-login[dot]example[.]xyz/a')[0].host, 'paypal-login.example.xyz');
});

test('a request to reply with the code just sent is read as asking for a code', async () => {
  const result = await analyze('Reply with the 6-digit code we just sent you to confirm it is you.');
  assert.ok(ids(result).includes('asks-for-code'));
  assert.notEqual(result.verdict, 'none');
});

test('a genuine one-time-code notice that says not to share it is not flagged', async () => {
  const result = await analyze('Your verification code is 482913. Do not share it with anyone.');
  assert.equal(result.verdict, 'none');
});

test('a message that says not to share the code but then asks for it is still flagged', async () => {
  const result = await analyze('Do not share this code with anyone else. Send us the verification code to confirm.');
  assert.ok(ids(result).includes('asks-for-code'));
});

test('an investment group pitch that moves to WhatsApp is a scam', async () => {
  const result = await analyze(
    'Hello, my analyst runs a VIP trading group with guaranteed returns of 5% daily. Message me on WhatsApp to join.',
  );
  assert.equal(result.verdict, 'scam');
  assert.ok(ids(result).includes('investment-pitch'));
});

test('a fee to withdraw profits is an advance-fee sign', async () => {
  const result = await analyze('Your profits are ready. Pay a tax of $400 to unlock your withdrawal.');
  assert.ok(ids(result).includes('advance-fee'));
  assert.notEqual(result.verdict, 'none');
});

test('an offer to recover lost crypto is flagged strongly', async () => {
  const result = await analyze('We can recover your lost funds from the scam. Fund recovery fee applies.');
  assert.ok(ids(result).includes('recovery-offer'));
  assert.notEqual(result.verdict, 'none');
});

test('a job that asks you to buy equipment is a scam', async () => {
  const result = await analyze(
    'We found your resume. No experience needed, daily pay $300. You will buy your own laptop and software from our vendor first.',
  );
  assert.equal(result.verdict, 'scam');
  assert.ok(ids(result).includes('job-fee'));
});

test('a cheque that you are asked to deposit and send part of is flagged', async () => {
  const result = await analyze('Deposit the cheque we mail you, then send the extra amount back by wire.');
  assert.ok(ids(result).includes('job-fee'));
});

test('a family emergency asking for bail money is flagged', async () => {
  const result = await analyze("Grandma it's me, I'm in jail after an accident. Please wire money for bail, don't tell mom.");
  assert.ok(ids(result).includes('family-emergency'));
  assert.notEqual(result.verdict, 'none');
});

test('ordinary talk about crypto, jobs and investing is not flagged', async () => {
  for (const text of [
    'I bought some bitcoin last year and it did okay.',
    'My new job starts Monday, they gave me a laptop on day one.',
    'The trading team at my bank had a meeting today, nothing exciting.',
    'We are hiring a part time designer. Please send your portfolio.',
  ]) {
    const result = await analyze(text);
    assert.equal(result.verdict, 'none', text);
  }
});

test('paying with crypto is still a strong sign', async () => {
  const result = await analyze('Please pay the invoice in bitcoin to this wallet address.');
  assert.equal(result.verdict, 'scam');
});

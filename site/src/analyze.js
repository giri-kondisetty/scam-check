import { textSignals } from './signals.js';
import { extractLinks, linkSignals } from './links.js';

const NEXT_STEPS = {
  reported: 'Do not open the link. Delete the message.',
  'asks-for-code': 'Do not share the code. Contact the company using the number on their official site or your card.',
  'unusual-payment': 'Do not pay. Talk to someone you trust before sending any money.',
  'remote-access': 'Do not install anything. Hang up, and call your bank on the number printed on your card.',
  default: 'Do not reply or click. Contact the organisation through a number or site you look up yourself.',
};

const DECISIVE = new Set(['reported', 'unusual-payment', 'remote-access', 'impersonates-brand', 'hidden-destination', 'lookalike-characters']);

export async function analyze(text, { blocklist } = {}) {
  const input = (text || '').trim();
  if (!input) return { verdict: 'empty', reasons: [], nextStep: '', blocklistChecked: false };

  const reasons = textSignals(input);
  const links = extractLinks(input);
  let blocklistChecked = false;

  for (const link of links) {
    reasons.push(...linkSignals(link));
    if (!blocklist) continue;
    try {
      if (await blocklist.isReported(link.host)) {
        reasons.push({
          id: 'reported',
          weight: 5,
          title: 'The link is on a list of reported scam sites',
          detail: `${link.host} has been reported as a phishing site.`,
          link: link.raw,
        });
      }
      blocklistChecked = true;
    } catch {
      blocklistChecked = false;
    }
  }

  if (links.length && reasons.some((r) => r.id === 'asks-for-code')) {
    reasons.push({
      id: 'code-and-link',
      weight: 2,
      title: 'It asks for a code and sends you to a link',
      detail: 'A request for a code together with a link is the usual shape of an account-takeover scam.',
    });
  }

  reasons.sort((a, b) => b.weight - a.weight);
  const score = reasons.reduce((sum, r) => sum + r.weight, 0);
  const decisive = reasons.some((r) => DECISIVE.has(r.id));
  const verdict = decisive || score >= 5 ? 'scam' : score >= 2 ? 'careful' : 'none';
  const top = reasons[0]?.id;
  const nextStep =
    verdict === 'none'
      ? 'No warning signs were found, which is not proof it is genuine. If it asks for money or details, check with the organisation directly.'
      : NEXT_STEPS[top] || NEXT_STEPS.default;

  return { verdict, reasons, nextStep, linkCount: links.length, blocklistChecked };
}

const SIGNALS = [
  {
    id: 'asks-for-code',
    weight: 3,
    title: 'It asks for a code or password',
    detail: 'A real company never asks you to send a one-time code, PIN or password.',
    patterns: [
      /\b(otp|one[- ]time (pass)?code|verification code|security code|auth(entication)? code|2fa code)\b/i,
      /\b(send|share|tell|give|confirm|enter|provide)\b[^.!?\n]{0,40}\b(pin|password|passcode|cvv|card number|login details)\b/i,
    ],
  },
  {
    id: 'unusual-payment',
    weight: 3,
    title: 'It asks for payment that cannot be reversed',
    detail: 'Gift cards, crypto and wire transfers are what scammers ask for, because the money cannot be recovered.',
    patterns: [
      /\b(gift ?cards?|itunes cards?|google play cards?|steam cards?|voucher codes?)\b/i,
      /\b(bitcoin|btc|usdt|crypto(currency)?|ethereum|wallet address)\b/i,
      /\b(western union|moneygram|wire transfer|bank transfer to)\b/i,
    ],
  },
  {
    id: 'remote-access',
    weight: 3,
    title: 'It asks you to install a remote-access app',
    detail: 'Apps like AnyDesk or TeamViewer let a stranger control your device and your banking.',
    patterns: [/\b(anydesk|teamviewer|rustdesk|quick ?support|remote (access|desktop|support))\b/i],
  },
  {
    id: 'urgency',
    weight: 2,
    title: 'It pressures you to act fast',
    detail: 'Scams rush you so you do not stop to check. A real organisation gives you time.',
    patterns: [
      /\b(urgent(ly)?|immediately|right away|act now|final (notice|warning)|last chance)\b/i,
      /\bwithin (the next )?\d+ ?(hours?|hrs?|minutes?|mins?)\b/i,
      /\b(will be|has been|is) (suspended|blocked|locked|closed|deactivated|terminated|restricted)\b/i,
    ],
  },
  {
    id: 'threat',
    weight: 2,
    title: 'It threatens you',
    detail: 'Threats of arrest, legal action or fines by message are a common scam tactic.',
    patterns: [/\b(arrest(ed)?|warrant|legal action|lawsuit|court|police case|deport(ed|ation)?|penalt(y|ies)|fine of)\b/i],
  },
  {
    id: 'prize',
    weight: 2,
    title: 'It promises money you did not expect',
    detail: 'Prizes, refunds and inheritances you never applied for are bait.',
    patterns: [
      /\b(you('ve| have)? won|winner|lottery|jackpot|prize|inheritance|unclaimed (funds|money)|compensation fund)\b/i,
      /\b(claim|collect) your (refund|reward|prize|payment|package)\b/i,
    ],
  },
  {
    id: 'easy-money',
    weight: 2,
    title: 'It offers easy money',
    detail: 'Guaranteed returns and pay for simple tasks are how investment and job scams start.',
    patterns: [
      /\b(guaranteed (returns?|profit)|double your (money|investment)|risk[- ]free (investment|profit)|\d+% (daily|weekly|per day|per week))\b/i,
      /\b(work from home|part[- ]time job|earn \$?\d+[^.!?\n]{0,20}(a|per) (day|week|hour)|like videos|rate (products|hotels))\b/i,
    ],
  },
  {
    id: 'advance-fee',
    weight: 2,
    title: 'It asks for a fee before you get something',
    detail: 'Paying a fee to release a prize, loan, parcel or job is an advance-fee scam.',
    patterns: [/\b(processing|release|clearance|customs|delivery|registration|activation|handling) (fee|charge)\b/i],
  },
  {
    id: 'new-number',
    weight: 2,
    title: 'Someone you know says they have a new number',
    detail: 'Scammers pose as family or friends with a "new number", then ask for money.',
    patterns: [/\b(hi|hey|hello) (mum|mom|dad|mama|papa)\b[^]{0,120}\b(new (number|phone)|lost my phone|broke(n)? my phone)\b/i, /\bthis is my new number\b/i],
  },
  {
    id: 'move-channel',
    weight: 1,
    title: 'It moves you to another app',
    detail: 'Being asked to continue on WhatsApp or Telegram takes you away from places that can protect you.',
    patterns: [/\b(contact|message|text|add|reach) (me|us|him|her|them)?[^.!?\n]{0,25}\b(on|via|through) (whatsapp|telegram|signal)\b/i],
  },
  {
    id: 'secrecy',
    weight: 1,
    title: 'It asks you to keep it secret',
    detail: 'Being told not to tell your bank or family is a strong sign of a scam.',
    patterns: [/\b(do not|don't|dont) (tell|inform|share with|mention)[^.!?\n]{0,30}\b(anyone|bank|family|police)\b/i, /\bkeep (this|it) (confidential|secret|between us)\b/i],
  },
];

export function textSignals(text) {
  const found = [];
  for (const signal of SIGNALS) {
    if (signal.patterns.some((p) => p.test(text))) {
      found.push({ id: signal.id, weight: signal.weight, title: signal.title, detail: signal.detail });
    }
  }
  return found;
}

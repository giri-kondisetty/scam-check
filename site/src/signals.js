const SIGNALS = [
  {
    id: 'asks-for-code',
    weight: 3,
    title: 'It asks for a code or password',
    detail: 'A real company never asks you to send a one-time code, PIN or password.',
    patterns: [
      /\b(otp|one[- ]time (pass)?code|verification code|security code|auth(entication)? code|2fa code)\b/i,
      /\b\d{4,8}[- ]digit (code|pin)\b/i,
      /\bcode (we|that we|just) (just )?(sent|texted)\b/i,
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
      /\b(pay|send|transfer|deposit|invest|buy)\b[^.!?\n]{0,40}\b(bitcoin|btc|usdt|crypto(currency)?|ethereum)\b/i,
      /\b(bitcoin|btc|usdt|ethereum) (atm|wallet|address|deposit)\b|\bwallet address\b/i,
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
    patterns: [
      /\b(processing|release|clearance|customs|delivery|registration|activation|handling|withdrawal|unlock|insurance|tax) (fee|charge|deposit)\b/i,
      /\bpay (a |the )?(tax|fee|deposit)\b[^.!?\n]{0,30}\b(withdraw|release|unlock|receive|claim)\b/i,
    ],
  },
  {
    id: 'new-number',
    weight: 2,
    title: 'Someone you know says they have a new number',
    detail: 'Scammers pose as family or friends with a "new number", then ask for money.',
    patterns: [/\b(hi|hey|hello) (mum|mom|dad|mama|papa)\b[^]{0,120}\b(new (number|phone)|lost my phone|broke(n)? my phone)\b/i, /\bthis is my new number\b/i],
  },
  {
    id: 'recovery-offer',
    weight: 3,
    title: 'It offers to recover money you lost',
    detail: 'People who have lost money to a scam are targeted again by "recovery" services that charge a fee and recover nothing.',
    patterns: [
      /\b(fund|funds|crypto|bitcoin|money) recovery\b/i,
      /\brecover(y of)? (your |the )?(lost |stolen )?(funds|money|crypto|bitcoin|investment)\b/i,
      /\bwe (can |will )?(get|recover|retrieve|trace) (back )?your (money|funds|crypto|bitcoin)\b/i,
    ],
  },
  {
    id: 'investment-pitch',
    weight: 2,
    title: 'It pitches an investment group or platform',
    detail: 'Trading groups, "signals", AI trading bots and mentors who promise profits are how most investment scams begin.',
    patterns: [
      /\b(trading|investment|investing) (group|signals?|bot|platform|mentor)\b/i,
      /\b(vip|private|exclusive) (group|channel|trading|investment)\b/i,
      /\b(insider (tips?|information)|ai[- ](powered|driven) trading|crypto (mining|trading) platform|forex signals?)\b/i,
      /\b(my|our) (analyst|mentor|assistant)\b[^.!?\n]{0,40}\b(invest|trade|profit|returns?)\b/i,
      /\b(your|my) (profits?|earnings|balance) (is|are) (ready|available|waiting)\b/i,
    ],
  },
  {
    id: 'job-fee',
    weight: 3,
    title: 'A job that asks you to pay, or to cash a cheque and send money on',
    detail: 'A real employer does not ask you to buy equipment, pay for training or checks, or deposit a cheque and send part of it elsewhere.',
    patterns: [
      /\b(buy|purchase|pay for|order)\b[^.!?\n]{0,25}\b(equipment|laptop|software|starter kit|training (materials|course)|supplies)\b/i,
      /\b(background check|training|equipment|onboarding|starter kit|account activation) (fee|cost|payment|deposit)\b/i,
      /\b(deposit|cash)( the| this| that| your)? (cheque|check)\b[^.!?\n]{0,80}\b(send|transfer|return|wire|forward|buy)\b/i,
    ],
  },
  {
    id: 'job-bait',
    weight: 2,
    title: 'An unrequested job offer with easy pay',
    detail: 'Offers you did not apply for, with no experience needed or no interview, are the usual start of a job scam.',
    patterns: [
      /\bwe (found|saw|came across) your (resume|cv|profile)\b/i,
      /\bno experience (is )?(needed|required|necessary)\b/i,
      /\b(hired|offered the (job|position)) (without|with no) (an )?interview\b/i,
      /\b(daily|weekly) (pay|payment|salary)\b[^.!?\n]{0,20}\$?\d/i,
    ],
  },
  {
    id: 'family-emergency',
    weight: 2,
    title: 'A family member in trouble who needs money now',
    detail: 'Voices and messages can be faked. Hang up and call the person on the number you already have, or ask for your agreed safe word.',
    patterns: [
      /\b(i('m| am)|he('s| is)|she('s| is)) (in (jail|custody|the hospital)|been (arrested|in an accident))\b[^]{0,160}\b(send|wire|transfer|pay|bail|money)\b/i,
      /\b(need|needs) (bail|bail money)\b/i,
    ],
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

const WARNS_NOT_TO_SHARE = /\b(do not|don't|never) (share|give|tell)\b/i;
const ASKS_TO_SEND = /\b(reply|send|forward|read (it |the code )?out)\b/i;

export function textSignals(text) {
  const found = [];
  const genuineCodeNotice = WARNS_NOT_TO_SHARE.test(text) && !ASKS_TO_SEND.test(text);
  for (const signal of SIGNALS) {
    if (signal.id === 'asks-for-code' && genuineCodeNotice) continue;
    if (signal.patterns.some((p) => p.test(text))) {
      found.push({ id: signal.id, weight: signal.weight, title: signal.title, detail: signal.detail });
    }
  }
  return found;
}

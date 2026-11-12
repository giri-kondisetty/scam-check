# Scam check

Paste a message or a link and see whether it shows signs of a scam.

Use it: https://giri-kondisetty.github.io/scam-check/

## What it tells you

One of three answers, with the reasons and what to do next:

- **Likely a scam**
- **Be careful**
- **No warning signs found**

It never says a message is safe. Finding no warning signs is not proof that a
message is genuine.

## How it works

Everything runs in your browser. Your message is not sent anywhere and is not
stored.

1. **Warning signs in the text.** Requests for codes or passwords, payment by
   gift card, crypto or wire transfer, remote-access apps, pressure, threats,
   unexpected prizes, easy money, advance fees, "new number" messages.
2. **Link checks.** Bare number addresses, look-alike characters, hidden
   destinations, shortened links, and well-known names on someone else's site.
3. **Reported scam sites.** Each link's site is compared with a list of
   reported phishing sites, rebuilt every day from
   [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database).

To check a link against the list, the page downloads one of 256 small files
chosen by a hash of the site name. The site name itself is never sent.

## Limits

- The text rules are English only.
- Rules miss scams that are worded in new ways, and can flag genuine messages.
- The reported-sites list only knows sites someone has already reported.
- Phone numbers are not checked yet.

## Run it yourself

```bash
npm test
node scripts/build-blocklist.mjs _site/data/blocklist
cp -r site/. _site/
npx serve _site
```

There is no build step and no dependencies.

## Layout

```
site/        the page: index.html, style.css, src/ (the checking rules)
scripts/     builds the reported-sites list
test/        tests for the rules
.github/     daily build and deploy, issue forms
```

## Contributing

A scam this missed, or a genuine message it flagged, is the most useful report.
Open an issue with the message text, with names and numbers removed.

## Licence

MIT

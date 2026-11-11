import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';

const SOURCE = 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt';
const PREFIX_LENGTH = 16;
const out = process.argv[2] || '_site/data/blocklist';

const response = await fetch(SOURCE);
if (!response.ok) throw new Error(`blocklist source returned ${response.status}`);
const hosts = (await response.text())
  .split('\n')
  .map((line) => line.trim().toLowerCase())
  .filter((line) => line && !line.startsWith('#') && line.includes('.'));
if (hosts.length < 1000) throw new Error(`blocklist source looks wrong: ${hosts.length} hosts`);

const shards = new Map();
for (const host of hosts) {
  const hash = createHash('sha256').update(host).digest('hex').slice(0, PREFIX_LENGTH);
  const key = hash.slice(0, 2);
  if (!shards.has(key)) shards.set(key, new Set());
  shards.get(key).add(hash);
}

await mkdir(out, { recursive: true });
for (let i = 0; i < 256; i += 1) {
  const key = i.toString(16).padStart(2, '0');
  await writeFile(path.join(out, `${key}.txt`), [...(shards.get(key) || [])].sort().join('\n'));
}
await writeFile(
  path.join(out, 'meta.json'),
  JSON.stringify({ source: SOURCE, hosts: hosts.length, built: new Date().toISOString() }),
);
console.log(`wrote ${hosts.length} hosts into 256 shards at ${out}`);

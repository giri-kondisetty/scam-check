export const PREFIX_LENGTH = 16;

export async function hostHash(host) {
  const bytes = new TextEncoder().encode(host);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, PREFIX_LENGTH);
}

export function candidateHosts(host) {
  const labels = host.split('.');
  const hosts = [];
  for (let i = 0; i <= labels.length - 2; i += 1) hosts.push(labels.slice(i).join('.'));
  return hosts;
}

export function createBlocklist(loadShard) {
  const shards = new Map();
  async function shard(key) {
    if (!shards.has(key)) {
      shards.set(key, loadShard(key).then((text) => new Set(text.split('\n').filter(Boolean))));
    }
    return shards.get(key);
  }
  return {
    async isReported(host) {
      for (const candidate of candidateHosts(host)) {
        const hash = await hostHash(candidate);
        const set = await shard(hash.slice(0, 2));
        if (set.has(hash)) return true;
      }
      return false;
    },
  };
}

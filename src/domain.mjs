import { capture } from './client.mjs';
export async function receiveCurrent(base, directory) {
 const { bytes, receipt } = await capture(base + '/index', directory);
 const data = JSON.parse(bytes);
 return { receipt: receipt.id, links: data.links, policy: data.policy };
}

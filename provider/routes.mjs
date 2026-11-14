export const initialState = { generation: 1, mode: 'normal', clock: 1000 };
export async function stop(state) {  }
export async function routes(context) {
 const { request, url, body, payload, state, json, text, binary } = context;

 if (url.pathname === '/index') return json({ links: ['/public/a', '/public/private/x', '/public/private/allow', '/public/%2fprivate/y'], policy: '/robots.txt' });
 if (url.pathname === '/robots.txt') {
   if (state.mode === 'unavailable') return text('维护中', 503);
   if (state.mode === 'absent') return text('', 404);
   return text(state.generation === 1 ? 'User-agent: *\nDisallow: /private\n\nUser-agent: CollectionBot\nDisallow: /public/private/\nAllow: /public/private/allow$\n' : 'User-agent: CollectionBot\nDisallow: /public/\n', 200, { etag: '"policy-' + state.generation + '"', 'cache-control': 'max-age=2' });
 }
 if (url.pathname.startsWith('/public/')) return json({ id: url.pathname, edition: state.generation, title: '公开馆藏资料' });

}

const BASE='/av';
const security={
  'X-Content-Type-Options':'nosniff',
  'Referrer-Policy':'strict-origin-when-cross-origin',
  'X-Frame-Options':'DENY',
  'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
};

function text(message,status,extra={}){
  return new Response(message,{status,headers:{...security,'Content-Type':'text/plain; charset=utf-8',...extra}});
}

export default {async fetch(request,env){
  try{
    const url=new URL(request.url);
    if(url.pathname!==BASE&&!url.pathname.startsWith(BASE+'/'))return text('Not found',404);
    if(!['GET','HEAD'].includes(request.method))return text('Method not allowed',405,{Allow:'GET, HEAD'});
    let pathname;
    try{pathname=decodeURIComponent(url.pathname)}catch{return text('Invalid path',400)}
    if(pathname.split('/').some(part=>part==='..'||part==='.')||pathname.includes('\\')||pathname.includes('\0'))return text('Invalid path',400);
    if(pathname===BASE){url.pathname=BASE+'/';return new Response(null,{status:308,headers:{...security,Location:url.toString()}})}
    url.pathname=pathname.slice(BASE.length)||'/';
    const response=await env.ASSETS.fetch(new Request(url,{method:request.method,headers:request.headers}));
    const headers=new Headers(response.headers);
    for(const[key,value]of Object.entries(security))headers.set(key,value);
    return new Response(response.body,{status:response.status,headers});
  }catch{return text('Something went wrong. Please try again.',500)}
}};

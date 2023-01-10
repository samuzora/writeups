# PutPixel Part 1

SieberrSec Industries' rival has released a new product called "PutPixel", and
we need some intelligence on it. Unfortunately, that's all the info we have; it
looks like they have been keeping their cards close to their chest.

http://putpixel.sieberrsec.live/

It looks like they may be using a popular "zero trust network service" which is
listed on a major stock exchange, as they only allow traffic from that
particular provider's IP ranges. Prove your skills and get through this NET!

---

After I did some googling, I found out that the network service in question is
Cloudflare. The challenge site seems to block all requests except those coming
from Cloudflare's IP range.

I tried all the usual HTTP headers but they all didn't seem to work. Because of
lack of time, I decided to move on to other challenges.

## Post CTF

After more googling, I came across [this
article](https://community.cloudflare.com/t/is-it-possible-to-spoof-http-requests-to-pretend-theyre-coming-from-the-ip-range-of-cloudflare-workers/50806/2).
Apparently, Cloudflare provides "workers", which are small functions that can be
turned into endpoints (similar to AWS Lambdas).

Using this worker functionality, it's possible to fetch a site from the worker
and return the output, thus successfully bypassing the Cloudflare IP whitelist.

So I registered for a Cloudflare account and spun up a worker with the following
function:

```js
export default {
  async fetch(request, env) {
    const { searchParams } = new URL(request.url);
    const path = searchParams.get("url");
    return fetch(`http://putpixel.sieberrsec.live/${path}`);
  }
}
```

This also allowed me to specify a path in case I need to access other pages
stuck behind the Cloudflare filter.

When I tried to visit my worker URL, there seemed to be some SSL error. So I
just `curl`ed the endpoint to get the flag.

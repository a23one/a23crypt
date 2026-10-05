# a23crypt.a23.one

The landing page. Plain HTML with no build step, served by Cloudflare
Workers static assets.

```bash
bun install
bun run dev        # http://localhost:8787
bun run deploy     # publish to Cloudflare
```

- `public/` is what gets deployed. `public/shared/a23crypt.js` is a
  JavaScript port of the a23crypt wire format (uncompressed records only),
  so ciphertexts sealed on the page decrypt with the Python library.
- `concepts/` holds the alternative design directions. They are not
  deployed; `bun run concepts` serves this folder so you can browse them
  at `/concepts/`.

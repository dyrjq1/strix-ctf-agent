# Server-side prototype pollution: non-destructive detection

Source: PortSwigger Web Security Academy, "Server-side prototype pollution" and
Gareth Heyes, "Server-side prototype pollution: Black-box detection without the DoS".

## Why this page exists

022 was lost to a self-inflicted wound: the first working payload wrote
`{"constructor":{"prototype":{"isAdmin":true,"polluted":"yes"}}}` and every route -
including a deliberately bogus one - started returning 500. From that point the agent
could no longer tell "route exists" from "route does not exist", and spent its last ten
calls probing blind.

PortSwigger names this exact failure as the reason server-side prototype pollution is
harder to test than the client-side variant:

1. **The DoS problem.** Polluting with *real* properties often breaks application
   functionality or brings the server down.
2. **Pollution persistence.** The write lasts for the lifetime of the Node process and
   there is no reset. A browser reload undoes client-side pollution; nothing undoes this.

So the first rule is not "find the gadget". It is **detect without destroying**.

## Rule 0: take a baseline before you mutate anything

Before the first pollution attempt, record three responses and keep them:

```
GET /<a path you know exists>     -> status, body length, content-type
GET /<a path you know is bogus>   -> status, body length, content-type
POST /<the merge endpoint> {}     -> status, body shape
```

Every later probe is compared against this table. If the bogus path's status changes,
**your own write broke the oracle** and every routing conclusion after it is invalid.
Stop probing, and either restart the target or find a non-reflected oracle below.

## Three non-destructive probes

All three change server behaviour in a way you can see, without writing a business
property. They are listed from safest to least safe.

### 1. JSON spaces override (safest, reversible)

Express reads `json spaces` from the app settings object. If the developer never set
it, the value is inherited from the prototype.

```http
POST /api/profile/update HTTP/1.1
Content-Type: application/json

{"__proto__":{"json spaces":10}}
```

Then re-request any endpoint that returns JSON and look at the **raw** bytes. If the
body is now indented by 10 spaces, the prototype was polluted. To undo, pollute it back
with the default:

```json
{"__proto__":{"json spaces":2}}
```

This is the only probe that can be turned off from the outside, which is why it is
tried first.

### 2. Status code override

Node's `http-errors` does `status = err.status || err.statusCode || status`. If an error
object has no own `status`, the inherited one is used.

1. Trigger an error response and note the default code (e.g. 400).
2. Pollute with an **obscure** code in the 400-599 range:

```json
{"__proto__":{"status":555}}
```

3. Trigger the same error again. A 555 means pollution worked.

The 400-599 range is not a style choice: Node coerces anything outside it to 500, so a
2xx or 6xx payload cannot distinguish "polluted" from "defaulted".

### 3. Charset override

`body-parser` resolves the request charset as `getCharset(req) or 'utf-8'`, and
`getCharset` returns `params.charset || ''` - an empty string when the header has no
charset, which is prototype-inheritable.

1. Pick a reflection point and send a UTF-7 encoded string in it, e.g. `+AGYAbwBv-`
   (which is `foo` in UTF-7). It comes back unchanged, because servers do not decode
   UTF-7 by default.
2. Pollute:

```json
{"__proto__":{"content-type":"application/json; charset=utf-7"}}
```

3. Repeat step 1. If `+AGYAbwBv-` now comes back as `foo`, pollution worked.

This one also works when the real request carries its own charset, because Node's
`_addHeaderLine` drops a duplicate header when a same-named property already exists on
the destination object - and that check walks the prototype chain.

## After detection: proving reach without breaking the app

Detection gives you "the merge is vulnerable". Reaching the flag is a separate step and
it is where 022 died. Order of preference:

1. **Reflected property.** Merge an arbitrary key and look for it in the JSON response.
   If it appears, you have a read channel that costs one call and changes nothing.
2. **One key at a time.** Never write three properties in one payload. Each extra
   property is another chance to break a code path you have not mapped.
3. **Re-check the baseline after each write.** A single `GET` to the bogus path tells
   you whether the oracle still works. If it does not, you have already lost the ability
   to test hypotheses; recover before continuing.

## The `constructor.prototype` trap

`{"__proto__":{...}}` and `{"constructor":{"prototype":{...}}}` are not equivalent in
practice:

- `__proto__` is a setter on `Object.prototype`; many merge implementations *skip* it,
  so it often fails silently.
- `constructor.prototype` goes through a normal property write, so naive recursive merge
  follows it. This is the one that usually works - and it is also the one that writes a
  `constructor` key onto the merged object, which is what shredded the response shape
  in 022.

Both should be tried; the second should never be tried with more than one payload key.

## Gadgets worth knowing (when you have a target to aim at)

- `child_process.fork()` / `execSync()` reached through a polluted options object
  (`shell`, `env`, `NODE_OPTIONS`).
- Template engines reading `escapeFunction`, `compileDebug`, `client` from options.
- Express `view options`, `json spaces`, `status`.
- Library "settings" objects passed by reference from a caller that did not supply them.

Do not go hunting gadgets before detection succeeds. Detection is one call; a gadget
hunt is ten.

## Anti-patterns (each of these cost a real run)

- Writing `isAdmin` / `role` / `polluted` **before** confirming the oracle still works.
- Concluding "all admin routes return 500, so there are no admin routes".
- Retrying the same pollution with more keys after the site already broke.
- Trusting a 500 as evidence about routing. After pollution, 500 is the new 404.

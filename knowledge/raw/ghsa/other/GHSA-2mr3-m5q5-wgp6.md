# Fiber is Vulnerable to Denial of Service via Flash Cookie Unbounded Allocation

**GHSA**: GHSA-2mr3-m5q5-wgp6 | **CVE**: CVE-2026-25899 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770, CWE-789

**Affected Packages**:
- **github.com/gofiber/fiber/v3** (go): <= 3.0.0

## Description

### Summary
The use of the `fiber_flash` cookie can force an unbounded allocation on any server. A crafted 10-character cookie value triggers an attempt to allocate up to 85GB of memory via unvalidated msgpack deserialization. No authentication is required. Every GoFiber v3 endpoint is affected regardless of whether the application uses flash messages.

### Details
Regardless of configuration, the flash cookie is checked:

```go
func (app *App) requestHandler(rctx *fasthttp.RequestCtx) {
	// Acquire context from the pool
	ctx := app.AcquireCtx(rctx)
	defer app.ReleaseCtx(ctx)

		// Optional: Check flash messages
		rawHeaders := d.Request().Header.RawHeaders()
		if len(rawHeaders) > 0 && bytes.Contains(rawHeaders, flashCookieNameBytes) {
			d.Redirect().parseAndClearFlashMessages()
		}
		_, err = app.next(d)
	} else {
		// Check if the HTTP method is valid
		if ctx.getMethodInt() == -1 {
			_ = ctx.SendStatus(StatusNotImplemented) //nolint:errcheck // Always return nil
			return
		}

		// Optional: Check flash messages
		rawHeaders := ctx.Request().Header.RawHeaders()
		if len(rawHeaders) > 0 && bytes.Contains(rawHeaders, flashCookieNameBytes) {
			ctx.Redirect().parseAndClearFlashMessages()
		}
}
```

The cookie value is hex-decoded and passed directly to msgpack deserialization with no size or content validation:

https://github.com/gofiber/fiber/blob/f8f34f642fb3682c341ede7816e7cf861aa7df89/redirect.go#L371

```go
// parseAndClearFlashMessages is a method to get flash messages before they are getting removed
func (r *Redirect) parseAndClearFlashMessages() {
	// parse flash messages
	cookieValue, err := hex.DecodeString(r.c.Cookies(FlashCookieName))
	if err != nil {
		return
	}

	_, err = r.c.flashMessages.UnmarshalMsg(cookieValue)
	if err != nil {
		return
	}

	r.c.Cookie(&Cookie{
		Name:   FlashCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}
```

The auto-generated `tinylib/msgp` deserialization reads a `uint32` array header from the attacker-controlled byte stream and passes it directly to `make()` with no bounds check:

https://github.com/gofiber/fiber/blob/f8f34f642fb3682c341ede7816e7cf861aa7df89/redirect_msgp.go#L242

```go
// UnmarshalMsg implements msgp.Unmarshaler
func (z *redirectionMsgs) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var zb0002 uint32
	zb0002, bts, err = msgp.ReadArrayHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return o, err
	}
	if cap((*z)) >= int(zb0002) {
		(*z) = (*z)[:zb0002]
	} else {
		(*z) = make(redirectionMsgs, zb0002)
	}
	for zb0001 := range *z {
		bts, err = (*z)[zb0001].UnmarshalMsg(bts)
		if err != nil {
			err = msgp.WrapError(err, zb0001)
			return o, err
		}
	}
	o = bts
	return o, err
}
```

where
 `zb0002, bts, err = msgp.ReadArrayHeaderBytes(bts)` translates the attacker-controlled value into the element count and `make(redirectionMsgs, zb0002)` performs the unbounded allocation

So we can craft a gofiber cookie that will force a huge allocation: 
`curl -H "Cookie: fiber_flash=dd7fffffff" http://localhost:5000/hello`

The cookie val is a hex-encoded msgpack array32 header:
- `dd` = msgpack array32 marker
- `7fffffff` = 2 147 483 647 elements

### Impact
Unauthenticated remote Denial of Service (CWE-789). Anyone running a gofiber v3.0.0 or v3 server is affected. The flash cookie parsing is hardcoded.

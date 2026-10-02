# Shared protocol helpers

The protocol layer provides the exact interfaces in the port contract, plus:

- `LoadCookies(t *Transport, state State) error` restores `state.session.cookies` into a tracking jar; invalid persisted entries are ignored as in the source.
- `SaveCookies(t *Transport, state State)` saves the jar into `state.session.cookies` with source-compatible cookie objects.
- `GenerateAuthCode(secret string, unix int64) (string, error)`.
- `GenerateConfirmationKey(secret, tag string, unix int64) (string, error)`.
- `CallService(ctx context.Context, t *Transport, iface, method string, request []byte, accessToken, httpMethod string) ([]byte, error)`.

Authenticated operations may use standard `Transport.Jar.Cookies(url)` and `SetCookies(url, cookies)`. Transport manages cookies manually across redirects and enforces the exact approved destination allowlist. Errors contain stable codes, never upstream bodies or sensitive inputs. Session and QR state maps use the source-compatible snake_case keys.

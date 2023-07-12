# Express bearer

An express middleware to decode and verify JWTs from bearer authorization headers.

## What does this do?

- loads signing keys from a JWKS endpoint using [jwks-rsa](https://github.com/auth0/node-jwks-rsa#readme)
- verifies and decodes a JWT from a Bearer authorization header using [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback)
- sets `req.user` to the verified decoded JWT payload (claims)

## Usage

```ts
import { bearerTokenMiddleware, BearerConfig } from '@makerxstudio/express-bearer'

const app = express()
const config: BearerConfig = {
  jwksUri: 'https://login.microsoftonline.com/<tenant ID>/discovery/v2.0/keys',
  verifyOptions: {
    issuer: 'https://login.microsoftonline.com/<tenant ID>/v2.0',
    audience: '<audience ID>',
  },
}

// add the bearer token middleware (to all routes)
app.use(bearerTokenMiddleware({ config }))
// or... add to a specific route
app.post('/api/admin/*', bearerTokenMiddleware({ config }))
// or... add to a specific route + make authentication mandatory
app.post('/api/admin/*', bearerTokenMiddleware({ config, tokenIsRequired: true }))

// access the user, check the roles claim
app.post('/api/admin/*', (req, res, next) => {
  const roles = (req.user?.roles as string[]) ?? []
  if (!roles.includes('Admin')) throw new Error('Authorization failed')
  next()
})
```

The middleware will:

- Return `401 Unauthorized` when the JWT fails decoding / verification
- Return `401 Unauthorized` if there is no `Bearer {token}` authorization header and `tokenIsRequired` is set to `true` (default is `false`)

## Options

`BearerAuthOptions`:

| Option            | Description                                                                                             |
| ----------------- | ------------------------------------------------------------------------------------------------------- |
| `config`          | The JWT handling config \*`BearerConfig` (or \*`BearerConfigCallback` for per-host config).             |
| `tokenIsRequired` | Controls whether requests with no `Bearer {token}` authorization header are rejected, default: `false`. |
| `logger`          | Optional logger implementation to log token validation errors, handler setup info entry etc.            |

JWT handling `config`:

| Option                         | Description                                                                                                                                                                                                                                                                     |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `jwksUri`                      | The endpoint to load signing keys via [jwks-rsa](https://github.com/auth0/node-jwks-rsa#readme)                                                                                                                                                                                 |
| `verifyOptions`                | The options passed into [jwt.verify](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback)                                                                                                                                              |
| `unauthorizedResponse`         | Optional. Callback of type `(req: Request, res: Response) => Response)` which provides a way to customise the HTTP response when the bearer token is required and not present, or the validation fails.<br>If not provided, a plain text 401 Unauthorized response is returned. |
| `explicitNoIssuerValidation`   | Optional. The default behaviour is to enforce issuer validation through `verifyOptions.issuer` to avoid security issues through misconfiguration.<br>If it's intentional to not validate the issuer of incoming tokens, set this property to `true`.                            |
| `explicitNoAudienceValidation` | Optional. The default behaviour is to enforce audience validation through `verifyOptions.audience` to avoid security issues through misconfiguration.<br>If it's intentional to not validate the audience of incoming tokens, set this property to `true`.                      |

### Multitenant apps

To specify per-host config, provide a \*`BearerConfigCallback` in the form of `(host: string) => BearerConfig`.

Note: the callback will only be called once per host (config is cached).

## Logging

Set the logger implementation to an object that fulfills the `Logger` definition:

```ts
type Logger = {
  error(message: string, ...optionalParams: unknown[]): void
  warn(message: string, ...optionalParams: unknown[]): void
  info(message: string, ...optionalParams: unknown[]): void
  verbose(message: string, ...optionalParams: unknown[]): void
  debug(message: string, ...optionalParams: unknown[]): void
}
```

Note: this type is compatible with [winston loggers](https://github.com/winstonjs/winston).

The following example uses console logging:

```ts
const logger: Logger = {
  error: (message: string, ...params: unknown[]) => console.error
  warn: (message: string, ...params: unknown[]) => console.warn
  info: (message: string, ...params: unknown[]) => console.info
  verbose: (message: string, ...params: unknown[]) => console.trace
  debug: (message: string, ...params: unknown[]) => console.debug
}

const config: BearerConfig = {
  jwksUri: ...,
  verifyOptions: { ... },
  logger,
}
```

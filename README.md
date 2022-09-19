# Express bearer

An express middleware to decode and verify JWTs from bearer authorization headers:

- loads signing keys from a JWKS endpoint using [jwks-rsa](https://github.com/auth0/node-jwks-rsa#readme)
- verifies and decodes a JWT from a Bearer authorization header using [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback)
- sets `req.user` to the verified decoded JWT payload (claims)

## Usage

```ts
const app = express()
const config: BearerConfig = {
  jwksUri: 'https://login.microsoftonline.com/<tenant ID>/discovery/v2.0/keys',
  verifyOptions: {
    issuer: 'https://login.microsoftonline.com/<tenant ID>/v2.0',
    audience: '<audience ID>',
  },
}
addBearerTokenValidationHandler({ app, config })
```

This code adds a request handler to `POST *` which:

- Returns `401 Unauthorised` when the JWT fails decoding / verification
- Returns `401 Unauthorised` when there is no `Bearer {token}` authorization header (unless `tokenIsOptional` is set to `true`)

## Options

The `addBearerTokenValidationHandler` accepts `BearerAuthOptions`:

| Option            | Description                                                                                  |
| ----------------- | -------------------------------------------------------------------------------------------- |
| `app`             | The express app which add the handler is added                                               |
| `config`          | The JWT handling config \*`BearerConfig` or callback to retrieve the config by host          |
| `protectRoute`    | The route on which to add the request handler, default: `'*'`                                |
| `tokenIsOptional` | Controls whether request without an authorization header are allowed, default: `false`       |
| `logger`          | Optional logger implementation to log token validation errors, handler setup info entry etc. |

JWT handling `config` is via \*`BearerConfig`:
| Option | Description |
| ----------------- | -------------------------------------------------------------------------------------------- |
| `jwksUri` | The endpoint to load signing keys via [jwks-rsa](https://github.com/auth0/node-jwks-rsa#readme) |
| `verifyOptions` | The options passed into [jwt.verify](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) |

If you wish to support multiple configurations / tenants, provide a `BearerConfigCallback` to return config according to `req.headers.host`. The callback will only be called once per host (config is cached).

## Examples

### Optional authentication

Setting `tokenIsOptional` to `true` will allow requests without any authorization header / bearer token.

```ts
const config: BearerConfig = {
  jwksUri: ..,
  verifyOptions: { ... },
  tokenIsOptional: true
}
```

### Custom route

Setting `protectRoute` controls the `POST` route that the handler is set up on, default: '`*`'.

```ts
app.post(protectRoute, handler)
```

See [Express JS Routing](http://expressjs.com/en/guide/routing.html) for options on route path configuration.

This example only adds the request handler to `/admin/*`:

```ts
const config: BearerConfig = {
  jwksUri: ..,
  verifyOptions: { ... },
  protectRoute = '/admin/*',
}
```

### Logging

Set the logger implementation to an object that fulfills the `Logger` interface:

```ts
type Logger = {
  error(message: string, ...optionalParams: unknown[]): void
  warn(message: string, ...optionalParams: unknown[]): void
  info(message: string, ...optionalParams: unknown[]): void
  verbose(message: string, ...optionalParams: unknown[]): void
  debug(message: string, ...optionalParams: unknown[]): void
}
```

Note, this type is compatible with [winston loggers](https://github.com/winstonjs/winston).

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
  jwksUri: ..,
  verifyOptions: { ... },
  logger,
}
```

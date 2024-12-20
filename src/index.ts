import type { Logger } from '@makerx/node-common'
import type { Request, RequestHandler, Response } from 'express'
import { decode, GetPublicKeyOrSecret, JwtPayload, verify, VerifyOptions } from 'jsonwebtoken'
import { JwksClient } from 'jwks-rsa'

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: JwtPayload
    }
  }
}

export interface BearerConfig {
  /**
   * The URL of the JSON Web Keys Sets (JWKS) document
   */
  jwksUri: string

  /**
   * The options used to verify incoming JSON Web Tokens (JWTs)
   */
  verifyOptions: VerifyOptions

  /**
   * Callback invoked when the token is required and is not present, or the validation fails.
   *
   * When not provided, a plain text 401 Unauthorized response is returned.
   */
  unauthorizedResponse?: (req: Request, res: Response) => Response

  /**
   * The default behaviour is to require that verifyOptions.issuer is set, for security purposes.
   * If the intended behaviour is to not validate the issuer, set this property to true.
   */
  explicitNoIssuerValidation?: boolean

  /**
   * The default behaviour is to require that verifyOptions.audience is set, for security purposes.
   * If the intended behaviour is to not validate the audience, set this property to true.
   */
  explicitNoAudienceValidation?: boolean
}

export type BearerConfigCallback = (hostName: string) => BearerConfig

export interface BearerAuthOptions {
  config: BearerConfig | BearerConfigCallback
  tokenIsRequired?: boolean
  logger?: Logger
}

const resolveConfig = (config: BearerConfig | BearerConfigCallback, host: string): BearerConfig => {
  if (typeof config === 'function') return config(host)
  return config
}

function validateVerifyOptions(verifyOptions: VerifyOptions, explicitNoIssuerValidation?: boolean, explicitNoAudienceValidation?: boolean) {
  if (!explicitNoIssuerValidation && !verifyOptions.issuer) {
    throw new Error(
      'You need to set verifyOptions.issuer, or set explicitNoIssuerValidation to true if you explicitly want to skip issuer validation'
    )
  }

  if (!explicitNoAudienceValidation && !verifyOptions.audience) {
    throw new Error(
      'You need to set verifyOptions.audience, or set explicitNoAudienceValidation to true if you explicitly want to skip audience validation'
    )
  }
}

function createGetKey(jwksClient: JwksClient): GetPublicKeyOrSecret {
  return ({ kid }, callback) => {
    jwksClient
      .getSigningKey(kid)
      .then((key) => callback(null, key.getPublicKey()))
      .catch((error) => callback(error))
  }
}

function verifyToken(jwt: string, getKey: GetPublicKeyOrSecret, verifyOptions: VerifyOptions): Promise<JwtPayload> {
  return new Promise((resolve, reject) => {
    verify(jwt, getKey, verifyOptions, (error, decoded) => {
      if (error) return reject(error)
      if (!decoded || typeof decoded === 'string') {
        return reject(new Error('Bearer token decoding failed'))
      }
      return resolve(decoded)
    })
  })
}

const cacheByHost: Record<string, { verifyOptions: VerifyOptions; jwksClient: JwksClient; getKey: GetPublicKeyOrSecret }> = {}
export const verifyForHost = (host: string, jwt: string, config: BearerConfig | BearerConfigCallback): Promise<JwtPayload> => {
  if (!cacheByHost[host]) {
    const { jwksUri, verifyOptions, explicitNoIssuerValidation, explicitNoAudienceValidation } = resolveConfig(config, host)
    validateVerifyOptions(verifyOptions, explicitNoIssuerValidation, explicitNoAudienceValidation)

    const jwksClient = new JwksClient({ jwksUri })
    cacheByHost[host] = {
      jwksClient,
      verifyOptions,
      getKey: createGetKey(jwksClient),
    }
  }
  const { verifyOptions, getKey } = cacheByHost[host]
  return verifyToken(jwt, getKey, verifyOptions)
}

const defaultUnauthorizedResponse = (_req: Request, res: Response) => res.status(401).send('Unauthorized').end()

export const bearerTokenMiddleware = ({ config, tokenIsRequired, logger }: BearerAuthOptions): RequestHandler => {
  const handler: RequestHandler = (req, res, next) => {
    const host = req.headers.host ?? ''
    const resolvedConfig = resolveConfig(config, host)
    const unauthorizedResponse = resolvedConfig.unauthorizedResponse ?? defaultUnauthorizedResponse

    if (!req.headers.authorization?.startsWith('Bearer ')) {
      if (!tokenIsRequired) return next()
      logger?.debug('Bearer token not supplied')
      return unauthorizedResponse(req, res)
    }

    const jwt = req.headers.authorization?.substring(7)
    verifyForHost(host, jwt, config)
      .then((claims) => {
        req.user = claims
        next()
      })
      .catch((error: unknown) => {
        logger?.error('Bearer token verification failed', { host: req.headers.host, error })
        unauthorizedResponse(req, res)
      })
  }

  return handler
}

export type VerifyOptionsCallback = (host: string) => VerifyOptions
export type IssuerVerifyOptions = { jwksUri: string; verifyOptions: VerifyOptions | VerifyOptionsCallback }

export interface MultiIssuerBearerAuthOptions {
  /**
   * The options used to verify incoming JSON Web Tokens (JWTs) for all supported issuers (keyed by issuer claim value).
   */
  issuerVerifyOptions: Record<string, IssuerVerifyOptions>

  tokenIsRequired?: boolean
  logger?: Logger

  /**
   * Callback invoked when the token is required and is not present, or the validation fails.
   *
   * When not provided, a plain text 401 Unauthorized response is returned.
   */
  unauthorizedResponse?: (req: Request, res: Response) => Response

  /**
   * The default behaviour is to require that verifyOptions.issuer is set, for security purposes.
   * If the intended behaviour is to not validate the issuer, set this property to true.
   */
  explicitNoIssuerValidation?: boolean

  /**
   * The default behaviour is to require that verifyOptions.audience is set, for security purposes.
   * If the intended behaviour is to not validate the audience, set this property to true.
   */
  explicitNoAudienceValidation?: boolean
}

const multiIssuerJwksClients: Record<string, JwksClient> = {}
export const verifyMultiIssuer = (
  host: string,
  jwt: string,
  {
    issuerVerifyOptions,
    explicitNoIssuerValidation,
    explicitNoAudienceValidation,
  }: Pick<MultiIssuerBearerAuthOptions, 'issuerVerifyOptions' | 'explicitNoIssuerValidation' | 'explicitNoAudienceValidation'>
): Promise<JwtPayload> => {
  const decoded = decode(jwt)
  if (!decoded || typeof decoded === 'string') throw new Error('Bearer token decoding failed')
  if (!decoded.iss) throw new Error('Bearer token does not contain an issuer claim')

  const options = issuerVerifyOptions[decoded.iss]
  if (!options) throw new Error(`Missing bearer token verify options for issuer: ${decoded.iss}`)

  const { jwksUri } = options
  if (!multiIssuerJwksClients[jwksUri]) multiIssuerJwksClients[jwksUri] = new JwksClient({ jwksUri })

  const verifyOptions = typeof options.verifyOptions === 'function' ? options.verifyOptions(host) : options.verifyOptions
  validateVerifyOptions(verifyOptions, explicitNoIssuerValidation, explicitNoAudienceValidation)

  return verifyToken(jwt, createGetKey(multiIssuerJwksClients[jwksUri]), verifyOptions)
}

export const multiIssuerBearerTokenMiddleware = ({
  unauthorizedResponse,
  tokenIsRequired,
  logger,
  issuerVerifyOptions,
  explicitNoIssuerValidation,
  explicitNoAudienceValidation,
}: MultiIssuerBearerAuthOptions): RequestHandler => {
  const handler: RequestHandler = (req, res, next) => {
    const unauthorizedHandler = unauthorizedResponse ?? defaultUnauthorizedResponse

    if (!req.headers.authorization?.startsWith('Bearer ')) {
      if (!tokenIsRequired) return next()
      logger?.debug('Bearer token not supplied')
      return unauthorizedHandler(req, res)
    }

    const jwt = req.headers.authorization?.substring(7)
    const host = req.headers.host ?? ''

    verifyMultiIssuer(host, jwt, { issuerVerifyOptions, explicitNoIssuerValidation, explicitNoAudienceValidation })
      .then((claims) => {
        req.user = claims
        next()
      })
      .catch((error: unknown) => {
        logger?.error('Bearer token verification failed', { host: req.headers.host, error })
        unauthorizedHandler(req, res)
      })
  }

  return handler
}

export default bearerTokenMiddleware
export { VerifyOptions }

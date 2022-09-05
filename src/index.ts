import type { Logger } from '@makerxstudio/node-common'
import type { Express, RequestHandler, Response } from 'express'
import { GetPublicKeyOrSecret, verify, VerifyOptions, JwtPayload } from 'jsonwebtoken'
import { JwksClient } from 'jwks-rsa'

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: Record<string, unknown>
    }
  }
}

export interface BearerConfig {
  jwksUri: string
  verifyOptions: VerifyOptions
}

export type BearerConfigCallback = (hostName: string) => BearerConfig

export interface BearerAuthOptions {
  app: Express
  config: BearerConfig | BearerConfigCallback
  protectRoute?: string
  tokenIsOptional?: boolean
  logger?: Logger
}

const cacheByHost: Record<string, { verifyOptions: VerifyOptions; jwksClient: JwksClient; getKey: GetPublicKeyOrSecret }> = {}
const verifyForHost = (host: string, jwt: string, config: BearerConfig | BearerConfigCallback): Promise<JwtPayload> => {
  if (!cacheByHost[host]) {
    const { jwksUri, verifyOptions } = typeof config === 'function' ? config(host) : config
    const jwksClient = new JwksClient({ jwksUri })
    cacheByHost[host] = {
      jwksClient,
      verifyOptions,
      getKey: ({ kid }, callback) => {
        jwksClient
          .getSigningKey(kid)
          .then((key) => callback(null, key.getPublicKey()))
          .catch((error) => callback(error))
      },
    }
  }
  const { verifyOptions, getKey } = cacheByHost[host]

  return new Promise<JwtPayload>((resolve, reject) => {
    verify(jwt, getKey, { ...verifyOptions, complete: false }, (error, decoded) => {
      if (error) return reject(error)
      if (!decoded || typeof decoded === 'string') {
        return reject('Bearer token decoding failed')
      }
      return resolve(decoded)
    })
  })
}

export const addBearerTokenValidationHandler = ({
  app,
  config,
  protectRoute = '*',
  tokenIsOptional = false,
  logger,
}: BearerAuthOptions): RequestHandler => {
  const unauthorized = (res: Response) => res.status(401).send('Unauthorized').end()
  const handler: RequestHandler = (req, res, next) => {
    if (!req.headers.authorization?.startsWith('Bearer ')) {
      if (tokenIsOptional) return next()
      logger?.debug('Bearer token not supplied')
      return unauthorized(res)
    }

    const jwt = req.headers.authorization?.substring(7)
    verifyForHost(req.headers.host ?? '', jwt, config)
      .then((claims) => {
        req.user = claims
        next()
      })
      .catch((error: unknown) => {
        logger?.error('Bearer token verfication failed', { host: req.headers.host, error })
        unauthorized(res)
      })
  }

  if (protectRoute) {
    app.post(protectRoute, handler)
    logger?.info(`Bearer token validation handler added to route POST ${protectRoute}`)
  }

  return handler
}

export { VerifyOptions }

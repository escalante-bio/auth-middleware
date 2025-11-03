import crypto from 'crypto';
import process from 'process';

import FastifyCookie from '@fastify/cookie';
import Fastify from 'fastify';
import jwt, {JwtPayload} from 'jsonwebtoken';
import * as oidClient from 'openid-client';

import {checkExists, checkState} from 'external/dev_april_corgi+/js/common/asserts';

const AUTH_COOKIE = 'authorization';
const OIDC_COOKIE = 'oidc';
const CIPHER_ALGORITHM = 'aes-256-gcm';
const CIPHER_AUTH_TAG_LENGTH = 16;
const CIPHER_KEY_LENGTH = 32;
const CIPHER_IV_LENGTH = 16;
const ENCRYPTION_ENCODING = 'base64';
const LOGIN_EXPIRATION_MS = 15 * 60 * 1000;
const SESSION_EXPIRATION_MS = 24 * 60 * 60 * 1000;

async function main(): Promise<void> {
  const server = Fastify({
    logger: true,
    trustProxy: true,
  });

  const organization =
    checkExists(process.env.ORGANIZATION_DOMAIN, 'Must specify the ORGANIZATION_DOMAIN env var');
  const issuerUrl = `https://${organization}`;

  const domain = checkExists(process.env.COOKIE_DOMAIN, 'Must specify the COOKIE_DOMAIN env var');
  server.register(FastifyCookie, {
    hook: 'onRequest',
    parseOptions: {
      domain: domain === 'localhost:5050' ? undefined : domain,
      path: '/',
      secure: domain !== 'localhost:5050',
    },
  });

  server.addHook('onRequest', (_, reply, done) => {
    reply
      .header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
      .header('Content-Security-Policy', `default-src 'self'`)
      .header('X-Frame-Options', 'DENY')
      .header('X-Content-Type-Options', 'nosniff');
    done();
  });

  const issuer = await oidClient.discovery(
    new URL('https://accounts.google.com'),
    checkExists(process.env.GOOGLE_CLIENT_ID, 'Must specify GOOGLE_CLIENT_ID'),
    checkExists(process.env.GOOGLE_CLIENT_SECRET, 'Must specify GOOGLE_CLIENT_SECRET'),
  );
  checkState(issuer.serverMetadata().supportsPKCE(), 'OIDC server must support PKCE');
  const encryptionKeyString = checkExists(process.env.AUTH_SECRET, 'Must specify AUTH_SECRET');
  if (encryptionKeyString.length !== CIPHER_KEY_LENGTH) {
    throw new Error(`AUTH_SECRET must be exactly ${CIPHER_KEY_LENGTH} characters long`);
  }
  const encryptionKey = Buffer.from(encryptionKeyString, 'utf8');
  const signingKey = checkExists(process.env.SIGNING_KEY, 'Must specify SIGNING_KEY');

  server.get<{Querystring: {rd?: string}}>('/login', async (request, reply) => {
    reply.clearCookie(AUTH_COOKIE);

    let source;
    try {
      source = new URL(decodeURIComponent(checkExists(request.query.rd)));
    } catch (e: unknown) {
      return reply.code(400).send('Bad request');
    }

    // We want to allow subdomains of .${organization} as redirect targets, but they must be HTTPS
    if (source.protocol !== 'https:' || !source.host.endsWith(`.${organization}`)) {
      return reply.code(400).send('Bad request');
    }

    const callbackUrl = `${request.protocol}://${request.host}/login/callback`;
    const codeVerifier = oidClient.randomPKCECodeVerifier();
    const state = oidClient.randomState();
    reply.setCookie(OIDC_COOKIE, encrypt(JSON.stringify({
      codeVerifier,
      created: new Date().getTime(),
      loginUrl: request.originalUrl,
      redirectUrl: source,
      state,
    }), encryptionKey), {
      httpOnly: true,
      maxAge: LOGIN_EXPIRATION_MS / 1000,
      // Lax to enable following links between domains
      sameSite: 'lax',
    });

    reply.redirect(
      String(
        oidClient.buildAuthorizationUrl(issuer, {
          code_challenge: await oidClient.calculatePKCECodeChallenge(codeVerifier),
          code_challenge_method: 'S256',
          hd: organization,
          redirect_uri: callbackUrl,
          scope: 'openid email',
          state,
        })));
  });

  server.get('/login/callback', async (request, reply) => {
    const cookie = request.cookies[OIDC_COOKIE];
    if (!cookie) {
      return reply.redirect('/login');
    }

    const {codeVerifier, created, loginUrl, redirectUrl, state} =
      JSON.parse(decrypt(cookie, encryptionKey));
    reply.clearCookie(OIDC_COOKIE);

    if (created + LOGIN_EXPIRATION_MS < new Date().getTime()) {
      console.error('Attempted login with expired session');
      return reply.redirect(loginUrl);
    }

    const originalUrl = `${request.protocol}://${request.host}${request.originalUrl}`;
    const tokenSet = await oidClient.authorizationCodeGrant(
      issuer, new URL(originalUrl), {
        expectedState: state,
        pkceCodeVerifier: codeVerifier,
      });
    const claims = tokenSet.claims();

    if (!claims) {
      console.error('Missing claims');
      return reply.code(403).send();
    }
    if (!claims.email_verified) {
      console.error('Email is unverified');
      return reply.code(403).send();
    }
    if (claims.hd !== organization) {
      console.error(`Email hd ${claims.hd} is not part ${organization}`);
      return reply.code(403).send();
    }

    const token = jwt.sign(
      {
        email: claims.email,
        subject: claims.sub,
      },
      signingKey,
      {
        algorithm: 'RS256',
        audience: organization,
        expiresIn: SESSION_EXPIRATION_MS / 1000,
        issuer: issuerUrl,
        notBefore: 0,
      }
    );
    reply.setCookie(AUTH_COOKIE, encrypt(token, encryptionKey), {
      httpOnly: true,
      maxAge: SESSION_EXPIRATION_MS / 1000,
      sameSite: 'lax',
    });
    console.log(`Successful login by ${claims.email} (${claims.sub})`);
    reply.redirect(redirectUrl);
  });

  server.get('/check', async (request, reply) => {
    const credential = request.cookies[AUTH_COOKIE];
    if (!credential) {
      return reply.code(401).send();
    }

    let decrypted;
    try {
      decrypted = decrypt(credential, encryptionKey);
    } catch (e: unknown) {
      console.error('Unable to decrypt the cookie:', e);
      reply.clearCookie(AUTH_COOKIE);
      return reply.code(403).send();
    }

    let decoded;
    try {
      decoded = jwt.verify(decrypted, signingKey, {
        algorithms: ['RS256'],
        audience: organization,
        issuer: issuerUrl,
      }) as JwtPayload;
    } catch (e: unknown) {
      console.error('Cookie JWT failed to verify:', e);
      return reply.code(403).send();
    }

    reply.header('Authorization', `Bearer ${decrypted}`);
    reply.header('X-User-Email', decoded.email);
    reply.header('X-User-ID', decoded.subject);
    reply.send('logged in');
  });

  server.get('/logout', async (_, reply) => {
    reply.clearCookie(AUTH_COOKIE);
    reply.clearCookie(OIDC_COOKIE);
    reply.send('logged out');
  });

  server.get('/favicon.ico', (_, reply) => {
    reply.status(404).send('No such file');
  });

  let port;
  if (process.env.PORT_HTTP) {
    port = Number(process.env.PORT_HTTP);
  } else {
    port = 5050;
  }
  server.listen({host: '::', port}, (err, address) => {
    if (err) {
      throw err;
    }
    console.log(`Running on ${address}`);
  });
}

function encrypt(value: string, key: Buffer): string {
  const iv = crypto.randomBytes(CIPHER_IV_LENGTH);
  const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, key, iv, {
    authTagLength: CIPHER_AUTH_TAG_LENGTH,
  });
  const encryptedVerifier = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);

  return Buffer.concat([iv, cipher.getAuthTag(), encryptedVerifier]).toString(ENCRYPTION_ENCODING);
}

function decrypt(value: string, key: Buffer): string {
  const b = Buffer.from(value, ENCRYPTION_ENCODING);
  const iv = b.subarray(0, CIPHER_IV_LENGTH);
  const authTag = b.subarray(CIPHER_IV_LENGTH, CIPHER_IV_LENGTH + CIPHER_AUTH_TAG_LENGTH);
  const encryptedVerifier = b.subarray(CIPHER_IV_LENGTH + CIPHER_AUTH_TAG_LENGTH);
  const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, key, iv, {
    authTagLength: CIPHER_AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);
  return (
    decipher.update(encryptedVerifier, /* inputEncoding= */ undefined, 'utf8') +
    decipher.final('utf8')
  );
}

(async () => {
  await main();
})();

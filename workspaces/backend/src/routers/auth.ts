import { z } from 'zod';
import { publicProcedure, router } from '../utils/trpc';
import jwt, { JwtPayload } from 'jsonwebtoken';
import dotenv from 'dotenv';
import { TRPCError } from '@trpc/server';
import { db } from '../db/db';
import { users } from '../db/schema/users';
import { eq } from 'drizzle-orm';

export interface DecodedToken extends JwtPayload {
  new_user?: boolean;
  verified_credentials?: {
    address: string;
    chain: string;
    id: string;
    name_service: object;
    public_identifier: string;
    wallet_name: string;
    wallet_provider: string;
    format: string;
  }[];
}

dotenv.config();

const publicKey = process.env.DYNAMIC_PUBLIC_KEY || '';

// `algorithms` is pinned explicitly. Without it `jsonwebtoken` will accept whichever
// algorithm the token's own header claims, which is the classic JWT confusion vector
// (an attacker re-signs a payload with `alg: none`, or downgrades an RS256 token to HS256
// and signs it with the public key as the HMAC secret). Dynamic issues ES256 tokens.
// The session cookie must be `SameSite=None` because the SPA and the API are served from
// different registrable domains; browsers would otherwise omit the cookie entirely.
//
// `SameSite=None` also means browsers DO attach this cookie to cross-site requests, so it
// must never be relied on as the CSRF defence. The actual protection is the strict
// `ALLOWED_ORIGINS` check on every mutating method in `src/index.ts` — keep the two in sync.
//
// `COOKIE_SAMESITE=lax` is the safe choice for any single-origin deployment.
// `algorithms` is pinned explicitly. Without it `jsonwebtoken` accepts whichever algorithm
// the token's own header claims, which is the classic JWT confusion vector: an attacker can
// re-sign a payload with `alg: none`, or downgrade an ES256 token to HS256 and sign it using
// the public key as the HMAC secret. Dynamic issues ES256 tokens, so only ES256 is accepted.
export const DYNAMIC_JWT_ALGORITHMS: jwt.Algorithm[] = ['ES256'];

// The session cookie must be `SameSite=None` because the SPA and the API are served from
// different registrable domains; browsers would otherwise omit the cookie entirely.
//
// `SameSite=None` also means browsers DO attach this cookie to cross-site requests, so it
// must never be relied on as the CSRF defence. The actual protection is the strict
// `ALLOWED_ORIGINS` check on every mutating method in `src/index.ts` — keep the two in sync.
//
// Set `COOKIE_SAMESITE=lax` for any single-origin deployment, which is strictly safer.
const cookieSameSite = (process.env.COOKIE_SAMESITE === 'lax' ? 'lax' : 'none') as
  | 'lax'
  | 'strict'
  | 'none';

const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: cookieSameSite,
  path: '/',
} as const;

export const authRouter = router({
  authUser: publicProcedure
    .input(
      z.object({
        authToken: z.string(),
        ensName: z.string().optional(),
        ensAvatar: z.string().optional(),
      }),
    )
    .mutation(async (opts) => {
      const token = opts.input.authToken;
      try {
        const decodedToken = await new Promise<DecodedToken>(
          (resolve, reject) => {
            jwt.verify(token, publicKey, { algorithms: DYNAMIC_JWT_ALGORITHMS }, (err, decoded) => {
              if (err) {
                reject(err);
              } else {
                resolve(decoded as DecodedToken);
              }
            });
          },
        );
        if (decodedToken.verified_credentials?.[0].address) {
          const lowerCaseAddress =
            decodedToken.verified_credentials[0].address.toLowerCase();

          const user = await db.query.users.findFirst({
            where: eq(users.address, lowerCaseAddress),
          });

          let ethAddress = null;
          let starknetAddress = null;

          // Iterate over verified credentials to find eth and starknet addresses
          decodedToken.verified_credentials?.forEach(credential => {
            if (credential.chain === 'eip155') { // Ethereum address
              ethAddress = credential.address.toLowerCase();
            } else if (credential.chain === 'starknet') { // StarkNet address
              starknetAddress = credential.address.toLowerCase();
            }
          });

          if (!user) {
            await db.insert(users).values({
              address: lowerCaseAddress, // save address as lowercase
              walletName: decodedToken.verified_credentials?.[0].wallet_name,
              walletProvider:
                decodedToken.verified_credentials?.[0].wallet_provider,
              publicIdentifier:
                decodedToken.verified_credentials?.[0].public_identifier,
              ethAddress: ethAddress,
              starknetAddress: starknetAddress,
              dynamicId: decodedToken.verified_credentials?.[0].id,
              ensName: opts.input.ensName,
              ensAvatar: opts.input.ensAvatar,
              createdAt: new Date(),
            });
          } else {
            await db
              .update(users)
              .set({
                walletName: decodedToken.verified_credentials?.[0].wallet_name,
                walletProvider:
                  decodedToken.verified_credentials?.[0].wallet_provider,
                publicIdentifier:
                  decodedToken.verified_credentials?.[0].public_identifier,
                dynamicId: decodedToken.verified_credentials?.[0].id,
                ethAddress: ethAddress,
                starknetAddress: starknetAddress,
                ensName: opts.input.ensName,
                ensAvatar: opts.input.ensAvatar,
                updatedAt: new Date(),
              })
              .where(
                eq(
                  users.address,
                  lowerCaseAddress, // save address as lowercase,
                ),
              );
          }
        }
        opts.ctx.res.cookie('JWT', opts.input.authToken, SESSION_COOKIE_OPTIONS);
        return;
      } catch (err) {
        console.error(err);

        throw new TRPCError({
          code: 'INTERNAL_SERVER_ERROR',
        });
      }
    }),

  logout: publicProcedure.mutation(async (opts) => {
    opts.ctx.res.clearCookie('JWT', { path: '/', secure: true, sameSite: cookieSameSite });
    opts.ctx.req.user = null;
    return;
  }),

  currentUser: publicProcedure.query(async (opts) => {
    try {
      if (opts.ctx.user) {
        return opts.ctx.user;
      }
      return null;
    } catch (err) {
      throw new TRPCError({ code: 'UNAUTHORIZED' });
    }
  }),
});

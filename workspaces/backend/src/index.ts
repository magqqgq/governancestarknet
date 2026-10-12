import express, { Express } from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { createExpressMiddleware } from '@trpc/server/adapters/express';
import { appRouter } from './routers';
import { createContext } from './utils/createContex';
import cookieParser from 'cookie-parser';
import { db } from './db/db';
import { users } from './db/schema/users';
import { eq } from 'drizzle-orm';
import { getUserByJWT } from './utils/helpers';
import multer from 'multer';
import { delegateRouter } from './routers/delegates';
import { notificationsRouter } from './routers/notifications';
//import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import morgan from 'morgan';

// 15 mins -> 250 reqs
/*
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 250,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});
 */

dotenv.config();

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const app: Express = express();
const port = process.env.PORT || 8000;

const fetchUserMiddleware = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  if (req.cookies?.JWT) {
    const userId: string | undefined = (await getUserByJWT(req.cookies.JWT))
      ?.id;
    if (!userId) {
      return next();
    }
    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      with: { delegationStatement: true },
    });
    if (user) {
      req.user = user;
    }
  }
  next();
};

// Xss defense
app.use(cookieParser());
app.use(fetchUserMiddleware);
// Rate limiter
//app.use(limiter);
morgan.token('decoded-url', (req: any) => decodeURIComponent(req.originalUrl));

app.use(
  morgan(':method :decoded-url :status :response-time ms\n', {
    skip: function (req: any, res: any) {
      return res.statusCode < 400; // Skip logging if status code is less than 400
    },
  }),
);

// Allowed browser origins for credentialed requests, e.g.
//   ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
//
// The list is normalised (trailing slashes stripped, lower-cased) so that a mismatch
// caused by a stray slash cannot silently widen or narrow access.
const allowedOrigins: string[] = (process.env.ALLOWED_ORIGINS ?? '')
  .split(',')
  .map((origin: string) => origin.trim().replace(/\/+$/, '').toLowerCase())
  .filter((origin: string) => origin.length > 0);

/**
 * Resolves the request's origin against the allowlist.
 *
 * Only the `Origin` header is consulted. The previous implementation fell back to
 * `x-forwarded-for`, which is a list of *client IP addresses* and is entirely
 * client-controllable — any attacker could send `X-Forwarded-For: https://app.example.com`
 * and pass the check.
 *
 * @returns true when the origin is allowed, or when the request is same-origin/non-browser.
 */
const isOriginAllowed = (req: any): boolean => {
  const rawOrigin = req.headers.origin;
  if (!rawOrigin) return false;

  const origin: string = String(rawOrigin).replace(/\/+$/, '').toLowerCase();
  if (allowedOrigins.length === 0) {
    // Fail closed. With no allowlist configured, no cross-origin browser request may carry
    // credentials; same-origin and server-to-server calls (which send no `Origin`) are
    // unaffected, so a correctly deployed single-origin app keeps working.
    return false;
  }
  return allowedOrigins.includes(origin);
};

/**
 * Rejects state-changing requests whose `Origin` is not explicitly allowlisted.
 *
 * The API authenticates with a `SameSite=None` cookie, which browsers do attach to
 * cross-site requests. That combination means CORS alone cannot stop CSRF: a simple
 * cross-site form POST is sent even when the response is blocked. Verifying `Origin` on
 * every mutating method is what actually stops the request from executing.
 */
const checkOriginMiddleware = (req: any, res: any, next: any) => {
  const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];
  if (SAFE_METHODS.includes(req.method)) {
    next();
    return;
  }

  if (!isOriginAllowed(req)) {
    res.status(403).send('Access Denied');
    return;
  }
  next();
};

app.use(checkOriginMiddleware);


// Headers
app.use(helmet());

app.use(
  cors({
    // Reflecting the caller's Origin back while allowing credentials means every website
    // on the internet can call this API as the logged-in user. The origin must be chosen
    // from the allowlist instead.
    origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
      if (!origin) {
        // Same-origin or non-browser caller (server-to-server, curl). No CORS headers.
        callback(null, false);
        return;
      }
      const normalized: string = origin.replace(/\/+$/, '').toLowerCase();
      callback(null, allowedOrigins.includes(normalized));
    },
    credentials: true,
  }),
);


app.get('/health', (req, res) => res.sendStatus(200));

app.use(
  '/trpc',
  upload.single('file'),
  createExpressMiddleware({
    router: appRouter,
    createContext,
  }),
);
app.use(
  '/api/delegates',
  createExpressMiddleware({
    router: delegateRouter,
    createContext,
  }),
);
app.use(
  '/api/notifications',
  createExpressMiddleware({
    router: notificationsRouter,
    createContext,
  }),
);

app.listen(port, () => {
  console.log(`Express app listening at http://localhost:${port}`);
});

export default app;

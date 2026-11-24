import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import process from 'node:process';
import { Readable } from 'node:stream';
import { createSqliteStorageDriver, type SqliteStorageDriver } from '@mcphub/storage-sqlite';
import type { Hono } from 'hono';
import {
  parseGatewayConfig,
  resolvePublicUrl,
  type GatewayConfig,
  type GatewayEnvInput,
} from './config.js';
import { createApp, type GatewayAppOptions } from './index.js';

/** Minimal signal event emitter interface compatible with `node:process`. */
export interface SignalTarget {
  on(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown;
  off(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown;
}

/** Options for starting the Node.js 26 HTTP server adapter. */
export interface NodeGatewayServerOptions {
  readonly env?: GatewayEnvInput;
  readonly createGatewayApp?: (options: GatewayAppOptions) => Hono;
}

/** Running Node.js 26 gateway HTTP server and SQLite driver lifecycle handle. */
export interface NodeGatewayServerHandle {
  readonly config: GatewayConfig;
  readonly storage: SqliteStorageDriver;
  readonly server: Server;
  readonly port: number;
  stop(): Promise<void>;
}

/**
 * Converts a Node.js `IncomingMessage` into a Web-Standard `Request` whose URL is derived
 * exclusively from the configured authoritative `APP_BASE_URL` origin.
 */
export function createNodeRequest(req: IncomingMessage, appBaseUrl: string): Request {
  const targetUrl = resolvePublicUrl(appBaseUrl, req.url ?? '/');
  const headers = new Headers();

  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) {
      for (const entry of value) {
        headers.append(key, entry);
      }
    } else if (value !== undefined) {
      headers.set(key, value);
    }
  }

  const method = req.method ?? 'GET';
  if (method === 'GET' || method === 'HEAD') {
    return new Request(targetUrl, { method, headers });
  }

  const bodyStream = Readable.toWeb(req) as unknown as BodyInit;
  const init: RequestInit & { duplex: 'half' } = {
    method,
    headers,
    body: bodyStream,
    duplex: 'half',
  };
  return new Request(targetUrl, init);
}

/**
 * Writes a Web-Standard `Response` to a Node.js `ServerResponse`, preserving multiple
 * `Set-Cookie` headers and omitting response body streaming on `HEAD` requests.
 */
export async function writeNodeResponse(
  response: Response,
  res: ServerResponse,
  method?: string,
): Promise<void> {
  res.statusCode = response.status;

  response.headers.forEach((value, key) => {
    if (key !== 'set-cookie') {
      res.setHeader(key, value);
    }
  });

  const setCookies = response.headers.getSetCookie();
  if (setCookies.length > 0) {
    res.setHeader('set-cookie', setCookies);
  }

  if (method === 'HEAD' || response.body === null) {
    res.end();
    return;
  }

  const reader = response.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    res.write(value);
  }

  res.end();
}

/**
 * Validates gateway configuration, initializes `SqliteStorageDriver` WAL migrations,
 * and binds the Node.js 26 HTTP server adapter for `@mcphub/gateway`.
 */
export async function createNodeGatewayServer(
  options?: NodeGatewayServerOptions,
): Promise<NodeGatewayServerHandle> {
  const config = parseGatewayConfig(options?.env ?? process.env);
  const storage = createSqliteStorageDriver({ filename: config.sqlitePath });

  try {
    await storage.migrate();
    const app = (options?.createGatewayApp ?? createApp)({ config, storage });

    const server = createServer((req, res) => {
      void (async () => {
        try {
          const request = createNodeRequest(req, config.appBaseUrl);
          const response = await app.fetch(request);
          await writeNodeResponse(response, res, req.method);
        } catch {
          res.statusCode = 500;
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ error: 'Internal Server Error' }));
        }
      })();
    });

    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => {
        reject(error);
      };
      server.once('error', onError);
      server.listen(config.port, config.host, () => {
        server.off('error', onError);
        resolve();
      });
    });

    const address = server.address() as AddressInfo;
    let stopPromise: Promise<void> | undefined;

    const stop = (): Promise<void> => {
      if (stopPromise === undefined) {
        stopPromise = (async () => {
          await new Promise<void>((resolve) => {
            server.close(() => {
              resolve();
            });
          });
          await storage.close();
        })();
      }
      return stopPromise;
    };

    return {
      config,
      storage,
      server,
      port: address.port,
      stop,
    };
  } catch (error) {
    await storage.close();
    throw error;
  }
}

/**
 * Starts the Node.js 26 gateway process and attaches `SIGINT`/`SIGTERM` handlers
 * for clean HTTP and SQLite WAL teardown.
 */
export async function runGatewayProcess(
  env: GatewayEnvInput = process.env,
  signalTarget: SignalTarget = process,
): Promise<NodeGatewayServerHandle> {
  const handle = await createNodeGatewayServer({ env });

  const shutdown = (): void => {
    signalTarget.off('SIGINT', shutdown);
    signalTarget.off('SIGTERM', shutdown);
    void handle.stop();
  };

  signalTarget.on('SIGINT', shutdown);
  signalTarget.on('SIGTERM', shutdown);

  return handle;
}

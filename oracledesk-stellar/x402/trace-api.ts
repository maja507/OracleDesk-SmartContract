import type { RequestHandler } from "express";
import express, { type Express, type Request, type Response } from "express";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactStellarScheme } from "@x402/stellar/exact/server";
import {
  parseTraceLocator,
  checkCidAgainstTraceHash,
  gatewayUrl,
  verifyTraceHash,
  type TraceRecord,
} from "./trace-verification.js";

export type { TraceRecord };

export interface TraceRepository {
  get(traceId: string): Promise<TraceRecord | undefined>;
  getFull?(traceId: string): Promise<(TraceRecord & { marketId?: bigint; agent?: string }) | undefined>;
  market_trace_count?(args: { market_id: bigint }): Promise<bigint>;
  market_trace_at?(args: { market_id: bigint; index: bigint }): Promise<bigint | null>;
  trace_count?(): Promise<bigint>;
}

export interface TracePaymentNetwork {
  network: "stellar:testnet" | "stellar:pubnet";
  payTo: string;
  facilitatorUrl: string;
  facilitatorApiKey?: string;
}

export interface TraceApiOptions {
  repository: TraceRepository;
  ipfsGateway: string;
  price: string;
  networks: TracePaymentNetwork[];
  fetchImpl?: typeof fetch;
}

export class MapTraceRepository implements TraceRepository {
  public constructor(private readonly records: ReadonlyMap<string, TraceRecord>) {}

  public async get(traceId: string): Promise<TraceRecord | undefined> {
    return this.records.get(traceId);
  }
}

async function loadVerifiedTrace(
  repository: TraceRepository,
  gateway: string,
  traceId: string,
  fetchImpl: typeof fetch,
): Promise<{ record: TraceRecord; content: unknown; verification: object } | undefined> {
  const record = await repository.get(traceId);
  if (!record) return undefined;

  const locator = parseTraceLocator(record.ipfsCid);
  if (locator.kind === "unsupported") {
    throw new Error(`Unsupported trace locator: ${locator.reason}`);
  }

  let url: string;
  if (locator.kind === "ipfs") {
    url = gatewayUrl(gateway, locator.cid, locator.path);
  } else {
    throw new Error("Local traces not supported in this context");
  }

  const cidCheck = checkCidAgainstTraceHash(locator, record.traceHash);

  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(`IPFS gateway returned HTTP ${response.status}`);
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  if (!verifyTraceHash(bytes, record.traceHash)) {
    throw new Error(`Trace ${traceId} failed on-chain hash verification`);
  }

  try {
    return {
      record,
      content: JSON.parse(new TextDecoder().decode(bytes)),
      verification: {
        traceHash: true,
        cid: cidCheck.level,
      },
    };
  } catch {
    throw new Error(`Trace ${traceId} is not valid JSON`);
  }
}

function createPaymentHandler(config: TracePaymentNetwork, options: TraceApiOptions): RequestHandler {
  const facilitator = new HTTPFacilitatorClient({
    url: config.facilitatorUrl,
    createAuthHeaders: config.facilitatorApiKey
      ? async () => {
          const headers = { Authorization: `Bearer ${config.facilitatorApiKey}` };
          return { verify: headers, settle: headers, supported: headers };
        }
      : undefined,
  });
  const x402Server = new x402ResourceServer(facilitator).register(
    config.network,
    new ExactStellarScheme(),
  );

  return paymentMiddleware(
    {
      "GET /traces/:traceId": {
        accepts: [{
          scheme: "exact",
          price: options.price,
          network: config.network,
          payTo: config.payTo,
        }],
        description: "Paid access to an OracleDesk reasoning trace",
      },
    },
    x402Server,
  );
}

export function createTraceApi(options: TraceApiOptions): Express {
  if (options.networks.length === 0) {
    throw new Error("At least one x402 Stellar payment network is required");
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  const app = express();

  for (const network of options.networks) {
    app.use(createPaymentHandler(network, options));
  }

  app.get("/traces/:traceId/meta", async (req: Request, res: Response) => {
    try {
      const traceId = Array.isArray(req.params.traceId)
        ? req.params.traceId[0]
        : req.params.traceId;

      const record = await options.repository.get(traceId);
      if (!record) {
        res.status(404).json({ error: "Trace not found" });
        return;
      }

      res.set("Cache-Control", "public, max-age=300");
      res.json({
        traceId,
        ipfsCid: record.ipfsCid,
        traceHash: record.traceHash,
        price: options.price,
        verification: { status: "pending" },
      });
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : "Metadata retrieval failed",
      });
    }
  });

  app.get("/.well-known/x402", (req: Request, res: Response) => {
    const manifest = {
      version: 1,
      resources: [
        {
          path: "/traces/:traceId",
          method: "GET",
          price: options.price,
          description: "Access to a single reasoning trace",
          networks: options.networks.map((n) => ({
            network: n.network,
            payTo: n.payTo,
          })),
        },
      ],
      discovery: {
        meta: "/traces/:traceId/meta",
      },
    };
    res.set("Cache-Control", "public, max-age=3600");
    res.json(manifest);
  });

  app.get("/traces/:traceId", async (req: Request, res: Response) => {
    try {
      const traceId = Array.isArray(req.params.traceId)
        ? req.params.traceId[0]
        : req.params.traceId;

      const result = await loadVerifiedTrace(
        options.repository,
        options.ipfsGateway,
        traceId,
        fetchImpl,
      );
      if (!result) {
        res.status(404).json({ error: "Trace not found" });
        return;
      }
      res.json({
        traceId: result.record.traceId,
        traceHash: result.record.traceHash,
        content: result.content,
        verification: result.verification,
      });
    } catch (error) {
      res.status(502).json({
        error: error instanceof Error ? error.message : "Trace retrieval failed",
      });
    }
  });

  return app;
}

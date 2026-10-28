import type { CheckResponse, HealthResponse, QueryResponse, StatsResponse } from "./types";

/** An HTTP error from the gateway, carrying its `detail` message. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    throw new ApiError(response.status, await errorMessage(response));
  }
  return (await response.json()) as T;
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "detail" in body) {
      const detail = (body as { detail: unknown }).detail;
      // FastAPI validation errors are a list of {msg, loc, ...}.
      if (Array.isArray(detail)) {
        return detail
          .map((d) => (d && typeof d === "object" && "msg" in d ? String(d.msg) : String(d)))
          .join("; ");
      }
      return String(detail);
    }
  } catch {
    // Not JSON: fall through to the status text.
  }
  return `${response.status} ${response.statusText}`.trim();
}

const post = <T,>(path: string, prompt: string) =>
  request<T>(path, { method: "POST", body: JSON.stringify({ prompt }) });

export const api = {
  health: () => request<HealthResponse>("/health"),
  stats: () => request<StatsResponse>("/stats"),
  check: (prompt: string) => post<CheckResponse>("/check", prompt),
  query: (prompt: string) => post<QueryResponse>("/query", prompt),
};

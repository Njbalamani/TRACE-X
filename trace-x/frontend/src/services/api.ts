// Thin fetch wrapper around the TRACE-X REST API.
const BASE = "/api";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function handle<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch { /* keep statusText */ }
    throw new ApiError(resp.status, detail);
  }
  return resp.json() as Promise<T>;
}

export async function get<T>(path: string): Promise<T> {
  return handle<T>(await fetch(`${BASE}${path}`));
}

export async function post<T>(path: string, body?: unknown): Promise<T> {
  return handle<T>(await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  }));
}

export async function put<T>(path: string, body: unknown): Promise<T> {
  return handle<T>(await fetch(`${BASE}${path}`, {
    method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  }));
}

export async function del<T>(path: string): Promise<T> {
  return handle<T>(await fetch(`${BASE}${path}`, { method: "DELETE" }));
}

export async function upload<T>(path: string, file: File, source = "", description = ""): Promise<T> {
  const form = new FormData();
  form.append("file", file);
  const qs = new URLSearchParams({ source, description });
  return handle<T>(await fetch(`${BASE}${path}?${qs}`, { method: "POST", body: form }));
}

export const api = { get, post, put, del, upload };

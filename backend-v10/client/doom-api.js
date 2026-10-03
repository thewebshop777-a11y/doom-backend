/** Shared API helper for web/app clients. Bearer session is authoritative. */
export const DOOM_API = {
  base: import.meta?.env?.VITE_DOOM_API_BASE || "http://localhost:8790",
  headers(json=false) {
    const h = {};
    const token = localStorage.getItem("doom_access_token");
    if (json) h["content-type"] = "application/json";
    if (token) h.authorization = `Bearer ${token}`;
    h["x-client"] = "app";
    return h;
  }
};

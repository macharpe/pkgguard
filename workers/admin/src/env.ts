export interface Env {
  PKG_INDEX: KVNamespace;
  DB: D1Database;
  /** The built dashboard. Reached only through the Worker, after the Access JWT is verified. */
  ASSETS: Fetcher;
  /** Starts a refresh run. The Workflow instance id is the run id. */
  REFRESH: Workflow<import("./refresh/launch.js").RefreshParams>;
  /** `<team>.cloudflareaccess.com` */
  TEAM_DOMAIN: string;
  /** Audience tag of the Access application. */
  ACCESS_AUD: string;
}

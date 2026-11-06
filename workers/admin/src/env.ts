export interface Env {
  PKG_INDEX: KVNamespace;
  DB: D1Database;
  /** `<team>.cloudflareaccess.com` */
  TEAM_DOMAIN: string;
  /** Audience tag of the dashboard Access application. */
  ACCESS_AUD_UI: string;
  /** Audience tag of the `/api/*` Access application. */
  ACCESS_AUD_API: string;
}

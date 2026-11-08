import type { Ecosystem } from "../ecosystem-ids.js";

export interface ParsedPackage {
  ecosystem: Ecosystem;
  /** npm scope including `@`, otherwise null. */
  namespace: string | null;
  /** Unscoped, as it appears in the URL. */
  name: string;
  version: string;
}

/** Append-only record of admin mutations. */
export async function audit(db: D1Database, ts: Date, actor: string, action: string, detail: string): Promise<void> {
  await db.prepare("INSERT INTO audit_log (ts, actor, action, detail) VALUES (?, ?, ?, ?)").bind(ts.toISOString(), actor, action, detail).run();
}

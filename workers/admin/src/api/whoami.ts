import { actorLabel, type Actor } from "../access-jwt.js";
import { json } from "../http.js";

export const whoami = (actor: Actor): Response => json({ actor, label: actorLabel(actor) });

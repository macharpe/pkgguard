import { actorLabel, type Actor } from "../access-jwt.js";
import type { WhoamiResponse } from "../api-types.js";
import { json } from "../http.js";

export const whoami = (actor: Actor): Response => {
  const body: WhoamiResponse = { actor, label: actorLabel(actor) };
  return json(body);
};

import { sendChat, type ChatMessage, type SendResult } from "@pkgguard/core";
import type { Env } from "./env.js";

/** Called through a wrapper: workerd throws "Illegal invocation" if fetch is stored and called as a property. */
const chatFetch = (url: string, init: RequestInit): Promise<Response> => fetch(url, init);

/** Never throws, and never logs the webhook. A missing webhook is a quiet no-op. */
export const postChat = (env: Pick<Env, "GCHAT_WEBHOOK">, message: ChatMessage): Promise<SendResult> => sendChat(chatFetch, env.GCHAT_WEBHOOK, message);

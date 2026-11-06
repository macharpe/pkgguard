import { CloudflareLogo } from "@cloudflare/kumo/components/cloudflare-logo";
import { Text } from "@cloudflare/kumo/components/text";
import type { WhoamiResponse } from "../../../src/api-types.js";
import { ThemeToggle } from "./ThemeToggle.js";

export function Header({ who }: { who: WhoamiResponse | null }) {
  return (
    <header className="border-b border-kumo-line bg-kumo-base">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-6 py-3">
        <div className="flex items-center gap-3">
          <CloudflareLogo className="h-5 w-auto" />
          <span className="h-5 w-px bg-kumo-line" aria-hidden="true" />
          <div className="leading-tight">
            <Text variant="heading3" as="h1">
              PkgGuard
            </Text>
            <Text variant="secondary" size="xs">
              Package registry security
            </Text>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {who ? (
            <Text variant="secondary" size="sm" truncate>
              {who.label}
            </Text>
          ) : null}
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}

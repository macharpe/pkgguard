import { Button } from "@cloudflare/kumo/components/button";
import { Moon, Sun } from "@phosphor-icons/react";
import { useEffect, useState } from "react";

type Mode = "light" | "dark";
const KEY = "pkgguard-mode";

const current = (): Mode => (document.documentElement.getAttribute("data-mode") === "dark" ? "dark" : "light");

export function ThemeToggle() {
  const [mode, setMode] = useState<Mode>(current);

  useEffect(() => {
    document.documentElement.setAttribute("data-mode", mode);
    try {
      localStorage.setItem(KEY, mode);
    } catch {
      /* private mode: the choice just will not persist */
    }
  }, [mode]);

  return (
    <Button
      variant="secondary"
      shape="square"
      size="sm"
      aria-label={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      onClick={() => setMode((m) => (m === "dark" ? "light" : "dark"))}
    >
      {mode === "dark" ? <Sun size={16} /> : <Moon size={16} />}
    </Button>
  );
}

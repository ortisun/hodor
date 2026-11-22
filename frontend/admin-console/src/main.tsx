import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-sans/latin-ext-400.css";
import "@fontsource/ibm-plex-sans/latin-ext-500.css";
import "@fontsource/ibm-plex-sans/latin-ext-600.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@astryxdesign/core/reset.css";
import "@astryxdesign/core/astryx.css";
import "@hodor-theme/hodor.css";
import "./layer-rules.css";
import "./console.css";

import { LayerProvider } from "@astryxdesign/core/Layer";
import { Theme } from "@astryxdesign/core/theme";
import { hodorTheme } from "@hodor-theme/hodor.js";
import { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { pathOf, type Place, placeOf, type Screen } from "./address";
import { App, type Mode } from "./App";
import { Client } from "./client";
import { chooseMessages } from "./messages";

const MODE_KEY = "hodor-console-mode";

/** The mode the person chose in this browser; the dark one until they choose. */
function rememberedMode(): Mode {
  try {
    return window.localStorage.getItem(MODE_KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

function Console({ start }: { start: Place }) {
  const [place, setPlace] = useState(start);
  const [mode, setMode] = useState<Mode>(rememberedMode);
  const client = useMemo(() => new Client(start.tenant), [start.tenant]);
  const text = useMemo(() => chooseMessages(navigator.languages), []);

  useEffect(() => {
    document.documentElement.lang = text.locale;
  }, [text]);

  // Back and forward move between screens without loading the console again.
  useEffect(() => {
    const moved = () => {
      const now = placeOf(window.location.pathname);
      if (now !== null && now.tenant === start.tenant) {
        setPlace(now);
      } else {
        // Another tenant, or not the console: a tab never changes tenant on its own.
        window.location.reload();
      }
    };
    window.addEventListener("popstate", moved);
    return () => window.removeEventListener("popstate", moved);
  }, [start.tenant]);

  const go = useCallback(
    (screen: Screen) => {
      window.history.pushState(null, "", pathOf(start.tenant, screen));
      setPlace({ tenant: start.tenant, screen });
    },
    [start.tenant],
  );
  const leave = useCallback((path: string) => window.location.assign(path), []);
  const changeMode = useCallback((chosen: Mode) => {
    setMode(chosen);
    try {
      window.localStorage.setItem(MODE_KEY, chosen);
    } catch {
      // The choice lasts for this visit only.
    }
  }, []);

  return (
    <Theme theme={hodorTheme} mode={mode}>
      <LayerProvider>
        <App place={place} client={client} text={text} mode={mode} changeMode={changeMode} go={go} leave={leave} />
      </LayerProvider>
    </Theme>
  );
}

const root = document.getElementById("root");
const start = placeOf(window.location.pathname);

// The server serves this application only at addresses of the console;
// anything else is left as an empty page.
if (root !== null && start !== null) {
  createRoot(root).render(<Console start={start} />);
}

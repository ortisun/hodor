import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@astryxdesign/core/reset.css";
import "@astryxdesign/core/astryx.css";
import "@hodor-theme/hodor.css";
import "./showcase.css";

import { createRoot } from "react-dom/client";
import { App } from "./App";

const root = document.getElementById("root");
if (root !== null) {
  createRoot(root).render(<App />);
}

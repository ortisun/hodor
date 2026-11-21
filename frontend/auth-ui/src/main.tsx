import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-sans/latin-ext-400.css";
import "@fontsource/ibm-plex-sans/latin-ext-500.css";
import "@fontsource/ibm-plex-sans/latin-ext-600.css";
import "../../design-system/tokens.css";
import "../../design-system/components.css";
import "./auth-ui.css";

import { createRoot } from "react-dom/client";
import { type NoticeName, noticeOf, type PageName, pathOf, placeOf, tokenOf } from "./address";
import { App } from "./App";
import { Client } from "./client";
import { chooseMessages } from "./messages";

const root = document.getElementById("root");
const place = placeOf(window.location.pathname);

// The server serves this application only at addresses `placeOf`
// understands; anything else is left as an empty page.
if (root !== null && place !== null) {
  const text = chooseMessages(navigator.languages);
  document.documentElement.lang = text.locale;

  const notice = noticeOf(window.location.search);
  if (notice !== null) {
    // Said once: reloading the page does not say it again.
    window.history.replaceState(null, "", window.location.pathname + window.location.hash);
  }

  const go = (page: PageName, told?: NoticeName) => {
    window.location.assign(pathOf(place.tenant, page, told));
  };

  createRoot(root).render(
    <App
      place={place}
      client={new Client(place.tenant)}
      text={text}
      notice={notice}
      token={tokenOf(window.location.hash)}
      go={go}
    />,
  );
}

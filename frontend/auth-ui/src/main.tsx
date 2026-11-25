import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-sans/latin-ext-400.css";
import "@fontsource/ibm-plex-sans/latin-ext-500.css";
import "@fontsource/ibm-plex-sans/latin-ext-600.css";
import "@astryxdesign/core/reset.css";
import "@astryxdesign/core/astryx.css";
import "./auth-ui.css";

import { Theme } from "@astryxdesign/core/theme";
import { createRoot } from "react-dom/client";
import {
  continuationOf,
  loginHintOf,
  type NoticeName,
  noticeOf,
  type PageName,
  pathOf,
  placeOf,
  providerAnswerOf,
  signInAgainPath,
  tokenOf,
  uiLocalesOf,
} from "./address";
import { App } from "./App";
import { defaultThemeSlug, themes } from "./astryx-themes";
import { Client } from "./client";
import { chooseMessages } from "./messages";

const root = document.getElementById("root");
const place = placeOf(window.location.pathname);

// The server serves this application only at addresses `placeOf`
// understands; anything else is left as an empty page.
if (root !== null && place !== null) {
  // The languages an application asked for come before the browser's own.
  const text = chooseMessages([...uiLocalesOf(window.location.search), ...navigator.languages]);
  document.documentElement.lang = text.locale;

  const notice = noticeOf(window.location.search);
  const providerAnswer = providerAnswerOf(window.location.search);
  // What a provider sent back is read once and taken out of the address,
  // so that the code stays out of the browser's history.
  const token = tokenOf(window.location.hash);
  // The token of a link to sign in is read once and taken out of the
  // address, so that it does not stay in the browser's history.
  if (place.page === "sign-in-link") {
    window.history.replaceState(null, "", window.location.pathname);
  }
  if (notice !== null || place.page === "provider-callback") {
    // Said once: reloading the page does not say it again.
    window.history.replaceState(null, "", window.location.pathname + window.location.hash);
  }

  const go = (page: PageName, told?: NoticeName) => {
    window.location.assign(pathOf(place.tenant, page, told));
  };

  createRoot(root).render(
    <Theme theme={themes[defaultThemeSlug]} mode="light">
      <App
        place={place}
        client={new Client(place.tenant)}
        text={text}
        notice={notice}
        token={token}
        go={go}
        leave={(url) => window.location.assign(url)}
        providerAnswer={providerAnswer}
        signInAgain={continuationOf(window.location.search) !== null}
        loginHint={loginHintOf(window.location.search)}
        afterSignIn={continuationOf(window.location.search) === "security" ? "security" : "account"}
        reauthenticate={() => window.location.assign(signInAgainPath(place.tenant))}
      />
    </Theme>,
  );
}

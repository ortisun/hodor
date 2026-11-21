import { type NoticeName, type PageName, pathOf, type Place, type ProviderAnswer } from "./address";
import type { Client } from "./client";
import type { Messages } from "./messages";
import { AccountPage } from "./pages/AccountPage";
import { AskPage } from "./pages/AskPage";
import { ComingBackPage } from "./pages/ComingBackPage";
import { FinishPage } from "./pages/FinishPage";
import { SignInPage } from "./pages/SignInPage";
import { Frame } from "./parts/Frame";

export interface AppProps {
  place: Place;
  client: Client;
  text: Messages;
  /** Something to tell the person, named by the page that sent them here. */
  notice: NoticeName | null;
  /** The token of a link from a message, when the address carries one. */
  token: string | null;
  go: (page: PageName, notice?: NoticeName) => void;
  /** Sends the browser to another site: an identity provider. */
  leave: (url: string) => void;
  /** What an identity provider put in the address, on the page it sends people back to. */
  providerAnswer: ProviderAnswer;
}

/** Shows the page the address names. */
export function App({ place, client, text, notice, token, go, leave, providerAnswer }: AppProps) {
  const { tenant } = place;
  const page = { tenant, client, text, go, leave, path: (name: PageName) => pathOf(tenant, name) };

  switch (place.page) {
    case "sign-in":
      return <SignInPage {...page} notice={notice} />;
    case "register":
      return <AskPage {...page} purpose="registration" />;
    case "recover":
      return <AskPage {...page} purpose="recovery" />;
    case "complete-registration":
      return <FinishPage {...page} purpose="registration" token={token} />;
    case "reset-password":
      return <FinishPage {...page} purpose="recovery" token={token} />;
    case "account":
      return <AccountPage {...page} />;
    case "provider-callback":
      return <ComingBackPage {...page} provider={place.provider ?? ""} answer={providerAnswer} />;
    default:
      return (
        <Frame tenant={tenant} title={text.pageNotFoundTitle} text={text}>
          <p className="auth-text">{text.pageNotFound}</p>
          <ul className="auth-links">
            <li>
              <a href={pathOf(tenant, "sign-in")}>{text.goToSignIn}</a>
            </li>
          </ul>
        </Frame>
      );
  }
}

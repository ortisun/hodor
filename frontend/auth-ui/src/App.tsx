import { type NoticeName, type PageName, pathOf, type Place, type ProviderAnswer } from "./address";
import type { Client } from "./client";
import type { Messages } from "./messages";
import { AccountPage } from "./pages/AccountPage";
import { AskPage } from "./pages/AskPage";
import { ComingBackPage } from "./pages/ComingBackPage";
import { AcceptInvitationPage } from "./pages/AcceptInvitationPage";
import { ConsentPage } from "./pages/ConsentPage";
import { FinishPage } from "./pages/FinishPage";
import { SecurityPage } from "./pages/SecurityPage";
import { SignInLinkPage } from "./pages/SignInLinkPage";
import { SignInPage } from "./pages/SignInPage";
import { SignOutPage } from "./pages/SignOutPage";
import { Frame } from "./parts/Frame";
import { PageLink, Ways, Words } from "./parts/Words";

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
  /** An application's request, or a change of factors, waits for a new sign-in. */
  signInAgain?: boolean;
  /** The identifier an application suggested, to fill the sign-in field. */
  loginHint?: string | null;
  /** Where a completed sign-in goes when nothing else is said. */
  afterSignIn?: PageName;
  /** Sends the person to sign in again and come back to the security page. */
  reauthenticate?: () => void;
}

/** Shows the page the address names. */
export function App({
  place,
  client,
  text,
  notice,
  token,
  go,
  leave,
  providerAnswer,
  signInAgain = false,
  loginHint = null,
  afterSignIn = "account",
  reauthenticate = () => undefined,
}: AppProps) {
  const { tenant } = place;
  const page = { tenant, client, text, go, leave, path: (name: PageName) => pathOf(tenant, name) };

  switch (place.page) {
    case "sign-in":
      return (
        <SignInPage
          {...page}
          notice={notice}
          signInAgain={signInAgain}
          loginHint={loginHint}
          afterSignIn={afterSignIn}
        />
      );
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
    case "sign-out":
      return <SignOutPage {...page} />;
    case "security":
      return <SecurityPage {...page} reauthenticate={reauthenticate} />;
    case "consent":
      return <ConsentPage {...page} />;
    case "accept-invitation":
      return <AcceptInvitationPage {...page} token={token} />;
    case "sign-in-link":
      return <SignInLinkPage {...page} token={token} />;
    case "provider-callback":
      return <ComingBackPage {...page} provider={place.provider ?? ""} answer={providerAnswer} />;
    default:
      return (
        <Frame tenant={tenant} title={text.pageNotFoundTitle} text={text}>
          <Words>{text.pageNotFound}</Words>
          <Ways>
            <li>
              <PageLink href={pathOf(tenant, "sign-in")}>{text.goToSignIn}</PageLink>
            </li>
          </Ways>
        </Frame>
      );
  }
}

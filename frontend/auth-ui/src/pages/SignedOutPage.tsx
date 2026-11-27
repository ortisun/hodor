import { useCallback, useEffect, useRef, useState } from "react";
import { Frame } from "../parts/Frame";
import { Words } from "../parts/Words";
import type { PageProps } from "./shared";

/** The longest the page waits for its frames before it goes on. */
export const FRAMES_WAIT_MS = 5000;

interface SignedOutPageProps extends PageProps {
  /** Goes on to the finish of an application's request to sign out, rather than to the sign-in page. */
  continuesLogout: boolean;
  /** How long to wait for the frames; five seconds unless a test says otherwise. */
  waitMs?: number;
}

/**
 * Where a person lands once they signed out in this browser: the
 * applications they signed in to are told, each in a hidden frame of its
 * own front-channel logout address, and the page then goes on. The
 * addresses come from the server, which made them when the session ended;
 * the page never reads them from its own address.
 */
export function SignedOutPage({ tenant, client, text, go, leave, continuesLogout, waitMs = FRAMES_WAIT_MS }: SignedOutPageProps) {
  const [frames, setFrames] = useState<string[] | null>(null);
  const loaded = useRef(0);
  const gone = useRef(false);

  const goOn = useCallback(() => {
    if (gone.current) {
      return;
    }
    gone.current = true;
    if (continuesLogout) {
      leave(`/t/${tenant}/oauth2/logout/finish`);
    } else {
      go("sign-in", "signed-out");
    }
  }, [continuesLogout, go, leave, tenant]);

  useEffect(() => {
    let current = true;
    client.signedOutFrames().then(
      (found) => {
        if (!current) {
          return;
        }
        if (found.length === 0) {
          goOn();
        } else {
          setFrames(found);
        }
      },
      () => {
        // Nothing to load: the person is signed out all the same.
        if (current) {
          goOn();
        }
      },
    );
    return () => {
      current = false;
    };
  }, [client, goOn]);

  useEffect(() => {
    if (frames === null) {
      return;
    }
    // A frame that never loads keeps nobody waiting longer than this.
    const timer = window.setTimeout(goOn, waitMs);
    return () => window.clearTimeout(timer);
  }, [frames, goOn, waitMs]);

  function frameLoaded() {
    loaded.current += 1;
    if (frames !== null && loaded.current >= frames.length) {
      goOn();
    }
  }

  return (
    <Frame tenant={tenant} title={text.signedOutTitle} text={text}>
      <Words announced>{text.signedOutTelling}</Words>
      {frames?.map((frame, index) => (
        <iframe
          // The same address may come twice only if two clients share it.
          key={`${index}-${frame}`}
          className="signed-out-frame"
          title={text.signedOutFrameTitle}
          src={frame}
          // The application's page runs its own script with its own
          // cookies, and can do nothing to this page.
          sandbox="allow-scripts allow-same-origin"
          referrerPolicy="no-referrer"
          aria-hidden="true"
          tabIndex={-1}
          onLoad={frameLoaded}
        />
      ))}
    </Frame>
  );
}

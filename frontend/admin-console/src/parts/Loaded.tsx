import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Spinner } from "@astryxdesign/core/Spinner";
import { VStack } from "@astryxdesign/core/VStack";
import { useCallback, useEffect, useState } from "react";
import { Failure } from "../client";
import { describe, type Messages } from "../messages";

export type Loading<T> = { state: "loading" } | { state: "failed"; failure: Failure } | { state: "loaded"; value: T };

export function asFailure(thrown: unknown): Failure {
  return thrown instanceof Failure ? thrown : new Failure(null, 500);
}

/**
 * Asks the server for something when a screen opens, and again when
 * asked. A session that ended is told to `onSignedOut`, once, by whoever
 * shows the failure.
 */
export function useLoaded<T>(load: () => Promise<T>): [Loading<T>, () => void, (value: T) => void] {
  const [loading, setLoading] = useState<Loading<T>>({ state: "loading" });
  const [turn, setTurn] = useState(0);

  useEffect(() => {
    let current = true;
    load().then(
      (value) => {
        if (current) {
          setLoading({ state: "loaded", value });
        }
      },
      (thrown: unknown) => {
        if (current) {
          setLoading({ state: "failed", failure: asFailure(thrown) });
        }
      },
    );
    return () => {
      current = false;
    };
  }, [load, turn]);

  const again = useCallback(() => {
    setLoading({ state: "loading" });
    setTurn((count) => count + 1);
  }, []);
  const replace = useCallback((value: T) => setLoading({ state: "loaded", value }), []);
  return [loading, again, replace];
}

/** What a screen shows while it waits. */
export function Waiting({ text }: { text: Messages }) {
  return (
    <VStack hAlign="center" paddingBlock={8}>
      <Spinner label={text.loading} />
    </VStack>
  );
}

/** What a screen shows when the server did not answer as hoped, with the way to try again. */
export function Failed({ failure, again, text }: { failure: Failure; again?: () => void; text: Messages }) {
  return (
    <Banner
      status="error"
      title={describe(failure, text)}
      role="alert"
      endContent={again ? <Button size="sm" label={text.tryAgain} onClick={again} /> : undefined}
    />
  );
}

import { Link } from "@astryxdesign/core/Link";
import { useEffect, useState } from "react";
import type { Permission } from "../client";
import { Identifier, shortened } from "../parts/Identifier";
import { follow, type ScreenProps } from "./shared";
import { nameOf } from "./UsersScreen";

type Kind = "user" | "group" | "organization";

const NEEDS: Record<Kind, Permission> = {
  user: "users:read",
  group: "groups:read",
  organization: "organizations:read",
};

/**
 * The names a screen has asked for, kept while it is open so that a
 * dialog or a reloaded list does not ask again. A lookup that fails is
 * forgotten, so that it is asked for again next time.
 */
export type Names = Map<string, Promise<string>>;

/** The names of one screen, for as long as it is open. */
export function useNames(): Names {
  const [names] = useState<Names>(() => new Map());
  return names;
}

interface NameOfProps extends Pick<ScreenProps, "client" | "me" | "text" | "go" | "path"> {
  of: Kind;
  id: string;
  known: Names;
}

/**
 * A user, a group or an organization named by its identifier, shown as a
 * link to its page with its name once the server gives it. Someone who
 * may not read that kind of thing sees the identifier, and nothing is
 * asked for them.
 */
export function NameOf({ of, id, client, me, text, go, path, known }: NameOfProps) {
  const allowed = me.permissions.includes(NEEDS[of]);
  const [name, setName] = useState<string | null>(null);

  useEffect(() => {
    if (!allowed) {
      return;
    }
    let current = true;
    const key = `${of} ${id}`;
    let found = known.get(key);
    if (found === undefined) {
      found =
        of === "user"
          ? client.getUser(id).then((user) => nameOf(user, text))
          : of === "group"
            ? client.getGroup(id).then((group) => group.name)
            : client.getOrganization(id).then((organization) => organization.name);
      known.set(key, found);
      found.catch(() => known.delete(key));
    }
    found.then(
      (shown) => {
        if (current) {
          setName(shown);
        }
      },
      () => {
        // Without its name, the link shows the identifier.
      },
    );
    return () => {
      current = false;
    };
  }, [allowed, of, id, client, text, known]);

  if (!allowed) {
    return <Identifier value={id} text={text} />;
  }
  const screen = { name: of, id } as const;
  return (
    <Link href={path(screen)} onClick={(event) => follow(event, go, screen)}>
      {name ?? <span className="console-mono">{shortened(id)}</span>}
    </Link>
  );
}

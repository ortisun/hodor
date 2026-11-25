import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useEffect, useState } from "react";
import { CLAIM_FIELDS, type ClaimField, type Failure, type Profile } from "../client";
import { describe, type Messages } from "../messages";
import { Field } from "../parts/Field";
import { Form } from "../parts/Form";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Submit } from "../parts/Submit";
import { PageLink, Ways, Words } from "../parts/Words";
import { asFailure, type PageProps } from "./shared";

/** The fields of the page, in the groups the person reads them in. */
const GROUPS: { heading: (text: Messages) => string; fields: ClaimField[] }[] = [
  {
    heading: (text) => text.profileNamesHeading,
    fields: ["given_name", "middle_name", "family_name", "nickname"],
  },
  {
    heading: (text) => text.profileAboutHeading,
    fields: ["gender", "birthdate", "zoneinfo"],
  },
  {
    heading: (text) => text.profilePagesHeading,
    fields: ["profile", "picture", "website"],
  },
  {
    heading: (text) => text.profilePhoneHeading,
    fields: ["phone_number"],
  },
  {
    heading: (text) => text.profileAddressHeading,
    fields: [
      "address.street_address",
      "address.locality",
      "address.region",
      "address.postal_code",
      "address.country",
      "address.formatted",
    ],
  },
];

/** What the browser may fill a field with, from what it knows of the person. */
const AUTOCOMPLETE: Record<ClaimField, string> = {
  given_name: "given-name",
  middle_name: "additional-name",
  family_name: "family-name",
  nickname: "nickname",
  gender: "sex",
  birthdate: "bday",
  zoneinfo: "off",
  profile: "url",
  picture: "photo",
  website: "url",
  phone_number: "tel",
  "address.formatted": "street-address",
  "address.street_address": "address-line1",
  "address.locality": "address-level2",
  "address.region": "address-level1",
  "address.postal_code": "postal-code",
  "address.country": "country-name",
};

/** The claim a refusal names: its detail starts with the claim's name. */
function refusedField(failure: Failure): ClaimField | null {
  const named = failure.detail?.split(" ")[0] ?? "";
  return (CLAIM_FIELDS as readonly string[]).includes(named) ? (named as ClaimField) : null;
}

/**
 * The person's own details: their name and the standard claims applications
 * may read with their consent. Nothing here is required.
 */
export function ProfilePage({ tenant, client, text, go, path }: PageProps) {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [claims, setClaims] = useState<Record<ClaimField, string> | null>(null);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [wrong, setWrong] = useState<ClaimField | "display_name" | null>(null);

  useEffect(() => {
    let current = true;
    const load = async (): Promise<Profile | null> =>
      (await client.session()) === null ? null : client.profile();
    load().then(
      (found) => {
        if (!current) {
          return;
        }
        if (found === null) {
          go("sign-in");
        } else {
          setProfile(found);
          setDisplayName(found.displayName);
          setClaims(found.claims);
        }
      },
      (thrown: unknown) => {
        if (current) {
          setFailure(asFailure(thrown));
        }
      },
    );
    return () => {
      current = false;
    };
  }, [client, go]);

  async function save(event: FormEvent) {
    event.preventDefault();
    if (busy || claims === null) {
      return;
    }
    setBusy(true);
    setSaved(false);
    setFailure(null);
    setWrong(null);
    try {
      const kept = await client.saveProfile(displayName, claims);
      setProfile(kept);
      setDisplayName(kept.displayName);
      setClaims(kept.claims);
      setSaved(true);
    } catch (thrown) {
      const failed = asFailure(thrown);
      if (failed.status === 401) {
        go("sign-in");
        return;
      }
      const field = failed.code === "identity.claim_invalid" ? refusedField(failed) : null;
      if (field !== null) {
        setWrong(field);
      } else if (failed.code === "identity.display_name_invalid") {
        setWrong("display_name");
      } else {
        setFailure(failed);
      }
    } finally {
      setBusy(false);
    }
  }

  const loaded = profile !== null && claims !== null;
  return (
    <Frame tenant={tenant} title={loaded ? text.profileTitle : text.loading} text={text}>
      {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}
      {saved ? <Notice kind="success">{text.profileSaved}</Notice> : null}
      {loaded ? (
        <>
          <Words quiet>{text.profileLead}</Words>
          <Form onSubmit={(event) => void save(event)}>
            <Field
              label={text.displayNameLabel}
              name="display_name"
              autoComplete="name"
              value={displayName}
              error={wrong === "display_name" ? text.displayNameInvalid : null}
              onChange={setDisplayName}
            />
            {GROUPS.map((group) => (
              <VStack as="fieldset" gap={3} key={group.fields[0]} className="auth-fieldset">
                <legend>{group.heading(text)}</legend>
                {group.fields.map((field) => (
                  <Field
                    key={field}
                    label={text.claimLabel(field)}
                    hint={text.claimHint(field) ?? undefined}
                    name={field}
                    autoComplete={AUTOCOMPLETE[field]}
                    verbatim={field !== "given_name" && field !== "middle_name" && field !== "family_name"}
                    value={claims[field]}
                    error={wrong === field ? text.claimInvalid(text.claimLabel(field)) : null}
                    onChange={(value) => setClaims({ ...claims, [field]: value })}
                  />
                ))}
                {group.fields[0] === "phone_number" && claims.phone_number !== "" ? (
                  <Words quiet>{profile.phoneNumberVerified ? text.phoneVerified : text.phoneNotVerified}</Words>
                ) : null}
              </VStack>
            ))}
            <Submit label={text.profileSave} busy={busy} text={text} />
          </Form>
          <Ways>
            <li>
              <PageLink href={path("account")}>{text.backToAccount}</PageLink>
            </li>
          </Ways>
        </>
      ) : null}
    </Frame>
  );
}

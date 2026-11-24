import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { CheckboxList, CheckboxListItem } from "@astryxdesign/core/CheckboxList";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { RadioList, RadioListItem } from "@astryxdesign/core/RadioList";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, type ReactNode, useState } from "react";
import { isIdentifier } from "../address";
import type { Unit, UnitKind, UnitSettings } from "../client";
import { describe, named, type Messages } from "../messages";
import { Ladder } from "../parts/Confirm";
import { asFailure } from "../parts/Loaded";

/** A unit where the tree puts it: how deep, and the names from the top down to it. */
export interface Placed {
  unit: Unit;
  /** 1 at the top of the organization. */
  depth: number;
  path: string;
}

/**
 * The units of an organization in the order of their tree: each unit
 * followed by the units below it, siblings by name. A unit whose parent
 * is not among them is shown at the top.
 */
export function treeOf(units: readonly Unit[]): Placed[] {
  const known = new Set(units.map((unit) => unit.id));
  const below = new Map<string | null, Unit[]>();
  for (const unit of units) {
    const parent = unit.parentId !== null && known.has(unit.parentId) ? unit.parentId : null;
    below.set(parent, [...(below.get(parent) ?? []), unit]);
  }
  const placed: Placed[] = [];
  const seen = new Set<string>();
  function walk(parent: string | null, depth: number, above: string) {
    const children = [...(below.get(parent) ?? [])].sort((one, other) => one.name.localeCompare(other.name));
    for (const unit of children) {
      if (seen.has(unit.id)) {
        continue;
      }
      seen.add(unit.id);
      const path = above === "" ? unit.name : `${above} / ${unit.name}`;
      placed.push({ unit, depth, path });
      walk(unit.id, depth + 1, path);
    }
  }
  walk(null, 1, "");
  return placed;
}

/** A unit and every unit below it, however deep. */
function withBelow(units: readonly Unit[], id: string): Set<string> {
  const found = new Set([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const unit of units) {
      if (unit.parentId !== null && found.has(unit.parentId) && !found.has(unit.id)) {
        found.add(unit.id);
        grew = true;
      }
    }
  }
  return found;
}

const TOP = "top";

interface UnitFormProps {
  /** The unit being changed; `null` to create one. */
  current: Unit | null;
  units: readonly Unit[];
  submit: (settings: UnitSettings) => Promise<Unit>;
  onDone: (unit: Unit) => void;
  onClose: () => void;
  text: Messages;
}

/**
 * Creates a unit, or renames it, changes its kind or moves it. A unit
 * cannot be put under itself nor under a unit below it, so those are
 * not offered as its parent.
 */
export function UnitForm({ current, units, submit, onDone, onClose, text }: UnitFormProps) {
  const [name, setName] = useState(current?.name ?? "");
  const [kind, setKind] = useState<UnitKind>(current?.kind ?? "unit");
  const [parent, setParent] = useState(current?.parentId ?? TOP);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const excluded = current === null ? new Set<string>() : withBelow(units, current.id);
  const parents = treeOf(units).filter((placed) => !excluded.has(placed.unit.id));
  const parentId = parent === TOP ? null : parent;
  const changed =
    current === null || name.trim() !== current.name || kind !== current.kind || parentId !== current.parentId;
  const filled = name.trim() !== "" && changed;

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      onDone(await submit({ name, kind, parentId }));
    } catch (thrown) {
      setMessage(describe(asFailure(thrown), text));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={560} purpose="form">
      <DialogHeader
        title={current === null ? text.createUnitTitle : text.changeUnitTitle(current.name)}
        subtitle={<Ladder action={current === null ? "createUnit" : "changeUnit"} text={text} />}
      />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {message !== null ? <Banner status="error" title={message} role="alert" /> : null}
          <TextInput label={text.nameLabel} value={name} onChange={setName} autoComplete="off" hasAutoFocus width="100%" />
          <VStack gap={1}>
            <Text>{text.kindLabel}</Text>
            <SegmentedControl
              label={text.kindLabel}
              value={kind}
              onChange={(value) => setKind(value === "department" ? "department" : "unit")}
            >
              <SegmentedControlItem value="unit" label={named(text.unitKinds, "unit")} />
              <SegmentedControlItem value="department" label={named(text.unitKinds, "department")} />
            </SegmentedControl>
          </VStack>
          <RadioList label={text.parentLabel} value={parent} onChange={setParent} size="sm">
            <RadioListItem value={TOP} label={text.topLevel} />
            {parents.map((placed) => (
              <RadioListItem key={placed.unit.id} value={placed.unit.id} label={placed.path} />
            ))}
          </RadioList>
          {current !== null ? <Text color="secondary">{text.moveCarries}</Text> : null}
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={current === null ? text.createUnit : text.saveUnit}
              isDisabled={!filled}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}

/** The units to choose from, by their place in the tree; nothing when there are none. */
function UnitChoice({
  units,
  value,
  onChange,
  text,
}: {
  units: readonly Unit[];
  value: string[];
  onChange: (value: string[]) => void;
  text: Messages;
}) {
  if (units.length === 0) {
    return null;
  }
  return (
    <CheckboxList label={text.memberUnitsLabel} value={value} onChange={onChange} isOptional>
      {treeOf(units).map((placed) => (
        <CheckboxListItem key={placed.unit.id} value={placed.unit.id} label={placed.path} />
      ))}
    </CheckboxList>
  );
}

interface MemberFormProps {
  organization: string;
  /** The member whose units are changed, shown as the screen shows them; `null` to put a new one. */
  current: { userId: string; unitIds: string[]; shown: ReactNode } | null;
  units: readonly Unit[];
  submit: (userId: string, unitIds: string[]) => Promise<void>;
  onClose: () => void;
  text: Messages;
}

/** Puts a user in the organization with some of its units, or replaces the units of a member. Level 1. */
export function MemberForm({ organization, current, units, submit, onClose, text }: MemberFormProps) {
  const [identifier, setIdentifier] = useState("");
  const [chosen, setChosen] = useState<string[]>(current?.unitIds ?? []);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const userId = current?.userId ?? identifier.trim().toLowerCase();

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || userId === "") {
      return;
    }
    if (!isIdentifier(userId)) {
      setMessage(text.notAnIdentifier);
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      // Kept in the order of the tree.
      await submit(
        userId,
        treeOf(units)
          .map((placed) => placed.unit.id)
          .filter((id) => chosen.includes(id)),
      );
    } catch (thrown) {
      setMessage(describe(asFailure(thrown), text));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={560} purpose="form">
      <DialogHeader
        title={current === null ? text.putMemberTitle(organization) : text.changeMemberUnitsTitle}
        subtitle={<Ladder action="putOrganizationMember" text={text} />}
      />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {message !== null ? <Banner status="error" title={message} role="alert" /> : null}
          {current === null ? (
            <TextInput
              label={text.userIdentifierLabel}
              description={text.userIdentifierHint}
              value={identifier}
              onChange={setIdentifier}
              autoComplete="off"
              autoCapitalize="none"
              hasSpellCheck={false}
              hasAutoFocus
              width="100%"
            />
          ) : (
            <Text>{current.shown}</Text>
          )}
          <UnitChoice units={units} value={chosen} onChange={setChosen} text={text} />
          <Text color="secondary">{current === null ? text.putMemberLead(organization) : text.changeMemberLead}</Text>
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button type="submit" variant="primary" label={text.saveMember} isDisabled={userId === ""} isLoading={busy} />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}

const LANGUAGES = ["en", "pt-BR"] as const;

interface InviteFormProps {
  organization: string;
  units: readonly Unit[];
  submit: (email: string, unitIds: string[], locale: string) => Promise<void>;
  onClose: () => void;
  text: Messages;
}

/**
 * Invites an email address. Level 1: before its button the form says
 * that a message with a link goes to the address, and what happens to
 * an earlier invitation. The link is never shown here.
 */
export function InviteForm({ organization, units, submit, onClose, text }: InviteFormProps) {
  const [email, setEmail] = useState("");
  const [chosen, setChosen] = useState<string[]>([]);
  const [locale, setLocale] = useState<string>(LANGUAGES.find((language) => language === text.locale) ?? "en");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const address = email.trim();

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || address === "") {
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      await submit(
        address,
        treeOf(units)
          .map((placed) => placed.unit.id)
          .filter((id) => chosen.includes(id)),
        locale,
      );
    } catch (thrown) {
      setMessage(describe(asFailure(thrown), text));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={560} purpose="form">
      <DialogHeader title={text.inviteTitle(organization)} subtitle={<Ladder action="invite" text={text} />} />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {message !== null ? <Banner status="error" title={message} role="alert" /> : null}
          <TextInput
            label={text.emailLabel}
            type="email"
            value={email}
            onChange={setEmail}
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            hasAutoFocus
            width="100%"
          />
          <UnitChoice units={units} value={chosen} onChange={setChosen} text={text} />
          <VStack gap={1}>
            <Text>{text.messageLanguageLabel}</Text>
            <SegmentedControl label={text.messageLanguageLabel} value={locale} onChange={setLocale}>
              {LANGUAGES.map((language) => (
                <SegmentedControlItem key={language} value={language} label={named(text.messageLanguages, language)} />
              ))}
            </SegmentedControl>
          </VStack>
          <Text color="secondary">{text.inviteConsequence(address === "" ? text.theAddress : address)}</Text>
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={text.sendInvitation}
              isDisabled={address === ""}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}

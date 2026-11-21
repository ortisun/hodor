import { Badge } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Icon } from "@astryxdesign/core/Icon";
import { Link } from "@astryxdesign/core/Link";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Plus } from "lucide-react";
import { type MouseEvent, useCallback, useState } from "react";
import { may } from "../actions";
import type { Provider } from "../client";
import { named, type Messages } from "../messages";
import { Failed, useLoaded, Waiting } from "../parts/Loaded";
import { ProviderForm } from "./ProviderForm";
import { Page, type ScreenProps } from "./shared";

export function ProviderStatus({ status, text }: { status: string; text: Messages }) {
  return (
    <Badge variant={status === "enabled" ? "success" : "neutral"} label={named(text.providerStatus, status)} />
  );
}

type Row = { id: string; provider: Provider };

export function ProvidersScreen({ client, me, text, go, path, say }: ScreenProps) {
  const load = useCallback(() => client.listProviders(), [client]);
  const [loading, again] = useLoaded<Provider[]>(load);
  const [adding, setAdding] = useState(false);

  function open(event: MouseEvent, provider: Provider) {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    go({ name: "provider", id: provider.id });
  }

  return (
    <Page
      title={text.providers}
      lead={text.providersLead}
      actions={
        may(me.permissions, "addProvider") ? (
          <Button variant="primary" label={text.addProvider} icon={<Icon icon={Plus} />} onClick={() => setAdding(true)} />
        ) : null
      }
    >
      {loading.state === "loading" ? <Waiting text={text} /> : null}
      {loading.state === "failed" ? <Failed failure={loading.failure} again={again} text={text} /> : null}
      {loading.state === "loaded" ? (
        <Table<Row>
          data={loading.value.map((provider) => ({ id: provider.id, provider }))}
          idKey="id"
          hasHover
          emptyState={<EmptyState title={text.noProviders} description={text.noProvidersHint} isCompact />}
          columns={[
            {
              key: "name",
              header: text.columnProvider,
              renderCell: ({ provider }) => (
                <Link href={path({ name: "provider", id: provider.id })} onClick={(event) => open(event, provider)}>
                  {provider.displayName}
                </Link>
              ),
            },
            {
              key: "alias",
              header: text.columnAlias,
              renderCell: ({ provider }) => <span className="console-mono">{provider.alias}</span>,
            },
            {
              key: "issuer",
              header: text.kindLabel,
              renderCell: ({ provider }) => <Text color="secondary">{named(text.providerKinds, provider.kind)}</Text>,
            },
            {
              key: "status",
              header: text.columnStatus,
              renderCell: ({ provider }) => <ProviderStatus status={provider.status} text={text} />,
            },
            {
              key: "creates",
              header: text.columnCreatesUsers,
              renderCell: ({ provider }) => (provider.createsUsers ? text.createsUsersYes : text.createsUsersNo),
            },
          ]}
        />
      ) : null}

      {adding ? (
        <ProviderForm
          adding
          text={text}
          submit={(added) => client.addProvider(added)}
          onClose={() => setAdding(false)}
          onDone={(provider) => {
            setAdding(false);
            say(text.providerAdded(provider.displayName));
            go({ name: "provider", id: provider.id });
          }}
        />
      ) : null}
    </Page>
  );
}

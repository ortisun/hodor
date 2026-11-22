import { Button } from "@astryxdesign/core/Button";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Icon } from "@astryxdesign/core/Icon";
import { Link } from "@astryxdesign/core/Link";
import { Table } from "@astryxdesign/core/Table";
import { Plus } from "lucide-react";
import { type MouseEvent, useCallback, useState } from "react";
import { may } from "../actions";
import type { Application } from "../client";
import { moment } from "../messages";
import { Failed, useLoaded, Waiting } from "../parts/Loaded";
import { ApplicationForm } from "./ApplicationForm";
import { ProviderStatus } from "./ProvidersScreen";
import { Page, type ScreenProps } from "./shared";

type Row = { id: string; application: Application };

export function ApplicationsScreen({ client, me, text, go, path, say }: ScreenProps) {
  const load = useCallback(() => client.listApplications(), [client]);
  const [loading, again] = useLoaded<Application[]>(load);
  const [adding, setAdding] = useState(false);

  function open(event: MouseEvent, application: Application) {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    go({ name: "application", id: application.id });
  }

  return (
    <Page
      title={text.applications}
      lead={text.applicationsLead}
      actions={
        may(me.permissions, "addApplication") ? (
          <Button variant="primary" label={text.addApplication} icon={<Icon icon={Plus} />} onClick={() => setAdding(true)} />
        ) : null
      }
    >
      {loading.state === "loading" ? <Waiting text={text} /> : null}
      {loading.state === "failed" ? <Failed failure={loading.failure} again={again} text={text} /> : null}
      {loading.state === "loaded" ? (
        <Table<Row>
          data={loading.value.map((application) => ({ id: application.id, application }))}
          idKey="id"
          hasHover
          emptyState={<EmptyState title={text.noApplications} description={text.noApplicationsHint} isCompact />}
          columns={[
            {
              key: "name",
              header: text.columnApplication,
              renderCell: ({ application }) => (
                <Link
                  href={path({ name: "application", id: application.id })}
                  onClick={(event) => open(event, application)}
                >
                  {application.name}
                </Link>
              ),
            },
            {
              key: "party",
              header: text.columnParty,
              renderCell: ({ application }) => (application.firstParty ? text.firstParty : text.thirdParty),
            },
            {
              key: "status",
              header: text.columnStatus,
              renderCell: ({ application }) => <ProviderStatus status={application.status} text={text} />,
            },
            {
              key: "created",
              header: text.columnCreated,
              renderCell: ({ application }) => moment(application.createdAt, text),
            },
          ]}
        />
      ) : null}

      {adding ? (
        <ApplicationForm
          current={null}
          text={text}
          submit={(settings) => client.addApplication(settings)}
          onClose={() => setAdding(false)}
          onDone={(application) => {
            setAdding(false);
            say(text.applicationAdded(application.name));
            go({ name: "application", id: application.id });
          }}
        />
      ) : null}
    </Page>
  );
}

import { useEffect, useState } from "preact/hooks";
import { whoAmI } from "@/api/auth/calls";
import { getPluginSchema } from "@/api/plugins/config/calls";
import type { ActionScope, PluginSchema } from "@/api/plugins/config/types";
import type { PluginInfo } from "@/api/plugins/types";
import { ActionRunner } from "./ActionRunner";
import { CollectionTable } from "./CollectionTable";
import { SettingsForm } from "./SettingsForm";
import { humanize } from "./format";

/**
 * Everything the selected plugin publishes: settings, collections and actions.
 *
 * It is assembled **only** from `GET …/schema` plus the token's scope
 * (`GET /auth/whoami`, read once), so a plugin nobody has written a line of UI
 * for shows up with its full form. An empty schema is a `200`, and the panel
 * says so instead of hiding itself: the plugin exists, it just declares nothing.
 *
 * The configuration is editable for a **disabled** plugin too (the server allows
 * it, which is how a plugin is fixed before it can run); only the actions need
 * the plugin loaded, and they say so.
 */

interface PluginConfigPanelProps {
  plugin: PluginInfo;
  /** Bumped when another client wrote this plugin's configuration. */
  reloadKey: number;
}

export function PluginConfigPanel({ plugin, reloadKey }: PluginConfigPanelProps) {
  const [schema, setSchema] = useState<PluginSchema | null>(null);
  const [scope, setScope] = useState<ActionScope | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  // The scope is asked once per panel: it cannot change without a new token,
  // and a new token reloads the page.
  useEffect(() => {
    let active = true;
    whoAmI()
      .then((answer) => {
        if (active) setScope(answer.scope);
      })
      .catch(() => {
        // Unreadable scope fails closed: nothing secret is offered for writing.
        if (active) setScope("agent");
      });
    return () => {
      active = false;
    };
  }, [plugin.name]);

  useEffect(() => {
    let active = true;
    getPluginSchema(plugin.name)
      .then((data) => {
        if (!active) return;
        setSchema(data);
        setFailure(null);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setSchema(null);
        setFailure(error instanceof Error ? error.message : String(error));
      });
    return () => {
      active = false;
    };
  }, [plugin.name, reloadKey]);

  if (failure !== null) {
    return (
      <div role="alert" class="mt-3 rounded-md border border-danger-800 bg-danger-900/20 px-3 py-2">
        <p class="text-xs font-medium text-danger-400">Configuration unavailable</p>
        <p class="mt-0.5 break-words text-[11px] text-neutral-400">{failure}</p>
      </div>
    );
  }

  if (schema === null || scope === null) {
    return <p class="mt-3 text-xs text-neutral-500">Loading configuration…</p>;
  }

  const empty =
    schema.settings.length === 0 && schema.collections.length === 0 && schema.actions.length === 0;
  if (empty) {
    return (
      <p class="mt-3 rounded-md border border-dashed border-neutral-800 px-3 py-3 text-center text-xs text-neutral-500">
        This plugin does not declare any configuration.
      </p>
    );
  }

  const loaded = plugin.loaded === true;

  return (
    <div class="mt-3 rounded-lg border border-neutral-800 bg-neutral-900/40 p-3">
      <div class="flex flex-wrap items-baseline justify-between gap-2">
        <h3 class="text-xs font-semibold uppercase tracking-wider text-neutral-300">
          {humanize(plugin.name)} configuration
        </h3>
        <span class="text-[11px] text-neutral-500">
          {scope === "full" ? "Token scope: full" : "Token scope: agent — secrets are read-only"}
        </span>
      </div>

      {schema.settings.length > 0 ? (
        <SettingsForm
          plugin={plugin.name}
          schema={schema}
          canWriteSecret={scope === "full"}
          reloadKey={reloadKey}
        />
      ) : null}

      {schema.collections.map((spec) => (
        <CollectionTable
          key={spec.name}
          plugin={plugin.name}
          spec={spec}
          canWriteSecret={scope === "full"}
          reloadKey={reloadKey}
        />
      ))}

      {schema.actions.map((spec) => (
        <ActionRunner
          key={spec.name}
          plugin={plugin.name}
          spec={spec}
          scope={scope}
          pluginLoaded={loaded}
        />
      ))}
    </div>
  );
}

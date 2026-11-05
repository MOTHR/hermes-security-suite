import {
  Button,
  Input,
  ScrollArea,
  SegmentedControl,
  Switch,
  useMutation,
  useQuery,
  useQueryClient,
} from "@hermes/plugin-sdk";
import { jsx } from "react/jsx-runtime";
import { useCallback, useState } from "react";

const PLUGIN_ID = "privacy-shield";
const API_PREFIX = "/config";

function usePluginConfig(ctx) {
  return useQuery({
    queryKey: [PLUGIN_ID, "config"],
    queryFn: () => ctx.rest(API_PREFIX, { method: "GET" }),
  });
}

function useSaveConfig(ctx) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (updates) =>
      ctx.rest(API_PREFIX, {
        method: "POST",
        body: { updates },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [PLUGIN_ID, "config"] }),
  });
}

function useRestoreTest(ctx) {
  return useMutation({
    mutationFn: (text) =>
      ctx.rest("/restore-test", {
        method: "POST",
        body: { text },
      }),
  });
}

function FieldRow({ label, children }) {
  return jsx("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      gap: "12px",
      padding: "8px 0",
      borderBottom: "1px solid var(--ui-stroke-secondary)",
    },
    children: [
      jsx("span", {
        key: "label",
        style: {
          color: "var(--ui-text-secondary)",
          fontSize: "13px",
          flexShrink: 0,
        },
        children: label,
      }),
      jsx("div", { key: "control", style: { minWidth: "140px" }, children }),
    ],
  });
}

function StringListEditor({ value, onChange, placeholder }) {
  const items = Array.isArray(value) ? value : [];
  const [draft, setDraft] = useState("");

  const add = useCallback(() => {
    const trimmed = draft.trim();
    if (!trimmed) return;
    if (items.includes(trimmed)) return;
    onChange([...items, trimmed]);
    setDraft("");
  }, [draft, items, onChange]);

  const remove = useCallback(
    (idx) => {
      const next = [...items];
      next.splice(idx, 1);
      onChange(next);
    },
    [items, onChange]
  );

  return jsx("div", {
    style: { display: "flex", flexDirection: "column", gap: "6px" },
    children: [
      ...items.map((item, idx) =>
        jsx("div", {
          key: `${item}-${idx}`,
          style: {
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "8px",
          },
          children: [
            jsx("span", {
              style: {
                color: "var(--ui-text-primary)",
                fontSize: "13px",
                wordBreak: "break-all",
              },
              children: item,
            }),
            jsx(Button, {
              key: "remove",
              variant: "ghost",
              size: "sm",
              onClick: () => remove(idx),
              children: "Remove",
            }),
          ],
        })
      ),
      jsx("div", {
        key: "add",
        style: { display: "flex", gap: "8px" },
        children: [
          jsx(Input, {
            value: draft,
            onChange: (e) => setDraft(e.target.value),
            placeholder,
            onKeyDown: (e) => e.key === "Enter" && add(),
          }),
          jsx(Button, { onClick: add, children: "Add" }),
        ],
      }),
    ],
  });
}

function ModeControl({ field, value, onChange }) {
  return jsx(SegmentedControl, {
    value,
    onChange: (v) => onChange(v),
    options: field.choices.map((c) => ({ value: c, label: c })),
  });
}

function renderPane(ctx) {
  const { data, isLoading, refetch } = usePluginConfig(ctx);
  const save = useSaveConfig(ctx);
  const test = useRestoreTest(ctx);
  const [local, setLocal] = useState({});
  const [testText, setTestText] = useState(
    "Call me at 030-12345678 or email test@example.com"
  );

  if (isLoading || !data) {
    return jsx("div", {
      style: { color: "var(--ui-text-secondary)", padding: "16px" },
      children: "Loading Privacy-Shield config...",
    });
  }

  const values = { ...data.values, ...local };

  const update = (key, value) => {
    setLocal((prev) => ({ ...prev, [key]: value }));
  };

  const changed = Object.keys(local).length > 0;

  return jsx(ScrollArea, {
    style: { padding: "16px" },
    children: [
      jsx("h2", {
        key: "title",
        style: { color: "var(--ui-text-primary)", margin: "0 0 12px" },
        children: `Privacy-Shield Controls (v${data.version})`,
      }),

      jsx("div", {
        key: "toolbar",
        style: { display: "flex", gap: "8px", marginBottom: "12px" },
        children: [
          jsx(Button, {
            onClick: () => refetch(),
            children: "Reload",
          }),
          jsx(Button, {
            disabled: !changed || save.isPending,
            onClick: () => save.mutate(local, { onSuccess: () => setLocal({}) }),
            children: save.isPending ? "Saving..." : "Save",
          }),
        ],
      }),

      ...Object.entries(data.fields).map(([key, field]) => {
        const value = values[key];
        if (field.type === "bool") {
          return jsx(FieldRow, {
            key,
            label: field.label,
            children: jsx(Switch, {
              checked: Boolean(value),
              onCheckedChange: (v) => update(key, v),
            }),
          });
        }
        if (field.type === "choice") {
          return jsx(FieldRow, {
            key,
            label: field.label,
            children: jsx(ModeControl, {
              field,
              value: String(value || field.default),
              onChange: (v) => update(key, v),
            }),
          });
        }
        if (field.type === "float") {
          return jsx(FieldRow, {
            key,
            label: field.label,
            children: jsx(Input, {
              type: "number",
              min: field.min,
              max: field.max,
              step: field.step,
              value: String(value ?? field.default),
              onChange: (e) => update(key, parseFloat(e.target.value)),
            }),
          });
        }
        if (field.type === "int") {
          return jsx(FieldRow, {
            key,
            label: field.label,
            children: jsx(Input, {
              type: "number",
              min: field.min,
              max: field.max,
              value: String(value ?? field.default),
              onChange: (e) => update(key, parseInt(e.target.value, 10)),
            }),
          });
        }
        if (field.type === "string_list") {
          return jsx("div", {
            key,
            style: {
              borderBottom: "1px solid var(--ui-stroke-secondary)",
              padding: "8px 0",
            },
            children: [
              jsx("div", {
                key: "label",
                style: {
                  color: "var(--ui-text-secondary)",
                  fontSize: "13px",
                  marginBottom: "8px",
                },
                children: field.label,
              }),
              jsx(StringListEditor, {
                key: "editor",
                value: Array.isArray(value) ? value : field.default,
                onChange: (v) => update(key, v),
                placeholder: "telegram:123456789",
              }),
            ],
          });
        }
        return jsx(FieldRow, {
          key,
          label: field.label,
          children: jsx(Input, {
            value: String(value ?? field.default ?? ""),
            onChange: (e) => update(key, e.target.value),
          }),
        });
      }),

      jsx("div", {
        key: "restore-test",
        style: {
          marginTop: "16px",
          paddingTop: "12px",
          borderTop: "1px solid var(--ui-stroke-secondary)",
        },
        children: [
          jsx("h3", {
            key: "rt-title",
            style: { color: "var(--ui-text-primary)", margin: "0 0 8px" },
            children: "Restore Smoke Test",
          }),
          jsx(Input, {
            key: "rt-input",
            value: testText,
            onChange: (e) => setTestText(e.target.value),
            style: { marginBottom: "8px" },
          }),
          jsx(Button, {
            key: "rt-btn",
            disabled: test.isPending,
            onClick: () => test.mutate(testText),
            children: test.isPending ? "Testing..." : "Test Restore",
          }),
          test.data &&
            jsx("pre", {
              key: "rt-result",
              style: {
                color: "var(--ui-text-secondary)",
                fontSize: "12px",
                marginTop: "8px",
                whiteSpace: "pre-wrap",
              },
              children: JSON.stringify(test.data, null, 2),
            }),
        ],
      }),
    ],
  });
}

export default {
  id: PLUGIN_ID,
  name: "Privacy-Shield Controls",
  register(ctx) {
    ctx.register({
      id: "controls",
      area: "panes",
      title: "Privacy-Shield",
      data: { placement: "right", width: "320px" },
      render: () => renderPane(ctx),
    });
  },
};

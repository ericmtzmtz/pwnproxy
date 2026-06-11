interface SeverityFilterProps {
  selected: string | null;
  onChange: (severity: string | null) => void;
}

const PILLS: { label: string; value: string | null }[] = [
  { label: "All", value: null },
  { label: "Critical", value: "critical" },
  { label: "High", value: "high" },
  { label: "Medium", value: "medium" },
  { label: "Low", value: "low" },
  { label: "Info", value: "info" },
];

const pillColors: Record<string, string> = {
  critical: "border-red-500/30 text-red-400 bg-red-900/20 hover:bg-red-900/40",
  high: "border-orange-500/30 text-orange-400 bg-orange-900/20 hover:bg-orange-900/40",
  medium: "border-yellow-500/30 text-yellow-400 bg-yellow-900/20 hover:bg-yellow-900/40",
  low: "border-blue-500/30 text-blue-400 bg-blue-900/20 hover:bg-blue-900/40",
  info: "border-neutral-500/30 text-neutral-400 bg-neutral-900 hover:bg-neutral-800",
};

export function SeverityFilter({ selected, onChange }: SeverityFilterProps) {
  return (
    <div class="flex flex-wrap items-center gap-2">
      {PILLS.map((pill) => {
        const isActive = selected === pill.value;
        const base = "cursor-pointer rounded-full border px-3 py-1 text-xs font-semibold transition-colors";
        const activeStyle = isActive && pill.value
          ? pillColors[pill.value] ?? "border-primary-500/30 bg-primary-900/20 text-primary-400"
          : isActive && !pill.value
            ? "border-primary-500 bg-primary-900/40 text-primary-300"
            : "border-neutral-700 text-neutral-500 hover:border-neutral-600 hover:text-neutral-300";
        return (
          <button
            key={pill.label}
            onClick={() => onChange(pill.value)}
            class={`${base} ${activeStyle}`}
          >
            {pill.label}
          </button>
        );
      })}
    </div>
  );
}

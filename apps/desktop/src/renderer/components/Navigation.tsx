import type { Tab } from "../App";

interface Props {
  activeTab: Tab;
  onChange: (tab: Tab) => void;
}

const TABS: Array<{ id: Tab; label: string }> = [
  { id: "issue", label: "Issue" },
  { id: "verify", label: "Verify" },
  { id: "batch", label: "Batch" },
  { id: "settings", label: "Settings" },
];

export function Navigation({ activeTab, onChange }: Props) {
  return (
    <div className="flex flex-wrap gap-1 bg-gray-100 rounded-lg p-1" role="tablist">
      {TABS.map((tab) => (
        <button
          key={tab.id}
          role="tab"
          aria-selected={activeTab === tab.id}
          onClick={() => onChange(tab.id)}
          className={`flex-1 min-w-[120px] rounded-md py-2 text-sm font-medium transition-colors ${
            activeTab === tab.id
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

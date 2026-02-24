interface Props {
  activeTab: string;
  onChange: (tab: string) => void;
}

const TABS = [
  { id: "builder", label: "Issue Credential" },
  { id: "delegated", label: "Delegated Issuance" },
  { id: "batch", label: "Batch Issuance" },
  { id: "verifier", label: "Verify" },
  { id: "revocation", label: "Revocation" },
  { id: "onboarding", label: "Onboarding" },
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

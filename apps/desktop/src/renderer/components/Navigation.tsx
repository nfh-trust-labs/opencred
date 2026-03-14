/**
 * Navigation — vertical sidebar with section groupings.
 *
 * Editorial Refined design: monospace labels, brand-light active fill,
 * blue dot indicator on active item, section headers.
 */

import type { Tab } from "../App";

interface Props {
  activeTab: Tab;
  onChange: (tab: Tab) => void;
}

interface NavItem {
  id: Tab;
  label: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const SECTIONS: NavSection[] = [
  {
    title: "Credentials",
    items: [
      { id: "issue", label: "Issue" },
      { id: "verify", label: "Verify" },
      { id: "batch", label: "Batch" },
    ],
  },
  {
    title: "Management",
    items: [
      { id: "settings", label: "Settings" },
    ],
  },
];

export function Navigation({ activeTab, onChange }: Props) {
  return (
    <nav className="oc-sidebar" role="navigation" aria-label="Main navigation">
      {SECTIONS.map((section) => (
        <div key={section.title}>
          <div className="oc-sidebar-section">{section.title}</div>
          {section.items.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onChange(item.id)}
                className={`oc-sidebar-item ${isActive ? "active" : ""}`}
                aria-current={isActive ? "page" : undefined}
              >
                <span
                  className={`h-1 w-1 rounded-full flex-shrink-0 ${
                    isActive ? "bg-brand-blue opacity-100" : "opacity-0"
                  }`}
                  aria-hidden="true"
                />
                {item.label}
              </button>
            );
          })}
        </div>
      ))}
    </nav>
  );
}

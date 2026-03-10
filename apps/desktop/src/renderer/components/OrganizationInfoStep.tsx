/**
 * OrganizationInfoStep — Quick Start step for entering organization details.
 *
 * Collects organization name and domain for domain verification.
 */

import { useState } from "react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";

interface OrganizationInfoStepProps {
  onSubmit: (info: { organizationName: string; domain: string }) => void;
  onBack: () => void;
}

export function OrganizationInfoStep({ onSubmit, onBack }: OrganizationInfoStepProps) {
  const [organizationName, setOrganizationName] = useState("");
  const [domain, setDomain] = useState("");

  const domainValid = domain.includes(".") && domain.length >= 4;
  const canSubmit = organizationName.trim().length > 0 && domainValid;

  return (
    <Card className="space-y-6">
      <div className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-900">Organization Details</h2>
        <p className="text-sm text-gray-600">
          Enter your organization name and domain. The domain will be used to
          verify your identity.
        </p>
      </div>

      <div className="space-y-4">
        <div>
          <label htmlFor="org-name" className="block text-xs font-medium text-gray-600">
            Organization Name
          </label>
          <input
            id="org-name"
            type="text"
            value={organizationName}
            onChange={(e) => setOrganizationName(e.target.value)}
            placeholder="e.g. Example University"
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>

        <div>
          <label htmlFor="domain" className="block text-xs font-medium text-gray-600">
            Domain
          </label>
          <input
            id="domain"
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="e.g. university.example"
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
          {domain.length > 0 && !domainValid && (
            <p className="mt-1 text-xs text-red-500">Enter a valid domain name</p>
          )}
        </div>
      </div>

      <div className="flex items-center justify-between pt-2">
        <Button variant="secondary" onClick={onBack}>
          Back
        </Button>
        <Button onClick={() => onSubmit({ organizationName: organizationName.trim(), domain: domain.trim() })} disabled={!canSubmit}>
          Next
        </Button>
      </div>
    </Card>
  );
}

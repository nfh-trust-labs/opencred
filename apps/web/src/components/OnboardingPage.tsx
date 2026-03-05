import { useState } from "react";
import { OpenCredClient } from "../api/client";

interface Props {
  apiUrl: string;
  token: string;
}

type OnboardingType = "type-b" | "type-d";

export function OnboardingPage({ apiUrl, token }: Props) {
  const [activeType, setActiveType] = useState<OnboardingType>("type-b");

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 text-sm text-gray-600">
        Issuers with an existing DSC (Type A) do not need onboarding — provide your DSC chain
        when issuing credentials via the Issue Credential page.
      </div>

      <div className="flex space-x-1 bg-gray-100 rounded-lg p-1">
        <button
          type="button"
          onClick={() => setActiveType("type-b")}
          className={`flex-1 rounded-md py-2 text-sm font-medium transition-colors ${
            activeType === "type-b"
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Type B (Domain)
        </button>
        <button
          type="button"
          onClick={() => setActiveType("type-d")}
          className={`flex-1 rounded-md py-2 text-sm font-medium transition-colors ${
            activeType === "type-d"
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Type D (Business VC)
        </button>
      </div>

      {activeType === "type-b" && <TypeBOnboarding apiUrl={apiUrl} token={token} />}
      {activeType === "type-d" && <TypeDOnboarding apiUrl={apiUrl} token={token} />}
    </div>
  );
}

// --- Type B: Domain Verification ---

function TypeBOnboarding({ apiUrl, token }: { apiUrl: string; token: string }) {
  const [domain, setDomain] = useState("");
  const [method, setMethod] = useState<"dns" | "http">("dns");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<{
    challengeId: string;
    challengeType: string;
    challengeValue: string;
    instructions: string;
  } | null>(null);
  const [confirmLoading, setConfirmLoading] = useState(false);
  const [confirmResult, setConfirmResult] = useState<{
    verified: boolean;
    issuerId?: string;
  } | null>(null);

  async function handleRequestChallenge() {
    if (!domain.trim()) return;
    setLoading(true);
    setError(null);
    setChallenge(null);
    setConfirmResult(null);

    try {
      const client = new OpenCredClient(apiUrl, token || undefined);
      const res = await client.onboardDomainVerify(domain.trim(), method);
      setChallenge(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Domain verification request failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleConfirm() {
    if (!challenge) return;
    setConfirmLoading(true);
    setError(null);

    try {
      const client = new OpenCredClient(apiUrl, token || undefined);
      const res = await client.onboardDomainConfirm(challenge.challengeId);
      setConfirmResult(res);
      if (!res.verified) {
        setError("Verification failed — ensure the challenge is properly configured");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Confirmation failed");
    } finally {
      setConfirmLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-blue-100 bg-blue-50 p-4">
        <p className="text-sm text-blue-800">
          Type B onboarding: Verify domain ownership via DNS TXT record or HTTP challenge.
        </p>
      </div>

      <div>
        <label htmlFor="domain-input" className="block text-sm font-medium text-gray-700">
          Domain
        </label>
        <input
          id="domain-input"
          type="text"
          value={domain}
          onChange={(e) => {
            setDomain(e.target.value);
            setChallenge(null);
            setConfirmResult(null);
          }}
          placeholder="example.com"
          className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Verification Method</label>
        <div className="flex gap-4">
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="radio"
              name="domain-method"
              checked={method === "dns"}
              onChange={() => setMethod("dns")}
              className="text-blue-600"
            />
            DNS TXT Record
          </label>
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="radio"
              name="domain-method"
              checked={method === "http"}
              onChange={() => setMethod("http")}
              className="text-blue-600"
            />
            HTTP Challenge
          </label>
        </div>
      </div>

      <button
        type="button"
        onClick={handleRequestChallenge}
        disabled={!domain.trim() || loading}
        className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
      >
        {loading ? "Requesting..." : "Request Challenge"}
      </button>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-3">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}

      {challenge && !confirmResult && (
        <div className="space-y-3">
          <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
            <p className="text-sm font-medium text-yellow-800">Challenge Created</p>
            <p className="mt-2 text-xs text-yellow-700">{challenge.instructions}</p>
            <div className="mt-2 rounded bg-yellow-100 p-2">
              <p className="font-mono text-xs text-yellow-900 break-all">
                {challenge.challengeValue}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={handleConfirm}
            disabled={confirmLoading}
            className="rounded-md bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-40"
          >
            {confirmLoading ? "Verifying..." : "Confirm Verification"}
          </button>
        </div>
      )}

      {confirmResult?.verified && (
        <div className="rounded-lg border border-green-200 bg-green-50 p-4">
          <p className="text-sm font-medium text-green-800">Domain verified successfully</p>
          {confirmResult.issuerId && (
            <p className="mt-1 text-xs text-green-600">Issuer ID: {confirmResult.issuerId}</p>
          )}
        </div>
      )}
    </div>
  );
}

// --- Type D: Business VC Upload ---

function TypeDOnboarding({ apiUrl, token }: { apiUrl: string; token: string }) {
  const [vcJson, setVcJson] = useState("");
  const [signingPreference, setSigningPreference] = useState<"delegated" | "interface">(
    "delegated",
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{
    delegationId: string;
    issuerId: string;
    scope: string[];
    validFrom: string;
    validUntil: string;
  } | null>(null);

  function handleFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      setVcJson(reader.result as string);
      setResult(null);
      setError(null);
    };
    reader.readAsText(file);
  }

  async function handleSubmit() {
    if (!vcJson.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    let businessCredential: Record<string, unknown>;
    try {
      businessCredential = JSON.parse(vcJson) as Record<string, unknown>;
    } catch {
      setError("Invalid JSON — please paste a valid Business Verifiable Credential");
      setLoading(false);
      return;
    }

    try {
      const client = new OpenCredClient(apiUrl, token || undefined);
      const res = await client.onboardBusinessVc(businessCredential, signingPreference);
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Business VC onboarding failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-blue-100 bg-blue-50 p-4">
        <p className="text-sm text-blue-800">
          Type D onboarding: Upload a Business Verifiable Credential to register and receive a
          delegation for credential issuance.
        </p>
      </div>

      <div>
        <label htmlFor="business-vc" className="block text-sm font-medium text-gray-700">
          Business Verifiable Credential (JSON)
        </label>
        <textarea
          id="business-vc"
          rows={10}
          value={vcJson}
          onChange={(e) => {
            setVcJson(e.target.value);
            setResult(null);
          }}
          placeholder="Paste your Business VC JSON here..."
          className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Signing Preference</label>
        <div className="flex gap-4">
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="radio"
              name="signing-preference"
              checked={signingPreference === "delegated"}
              onChange={() => setSigningPreference("delegated")}
              className="text-blue-600"
            />
            Delegated Signing
          </label>
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="radio"
              name="signing-preference"
              checked={signingPreference === "interface"}
              onChange={() => setSigningPreference("interface")}
              className="text-blue-600"
            />
            Interface Signing
          </label>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={handleSubmit}
          disabled={!vcJson.trim() || loading}
          className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
        >
          {loading ? "Submitting..." : "Submit Business VC"}
        </button>
        <label className="cursor-pointer rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50">
          Upload JSON File
          <input
            type="file"
            accept=".json"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFile(file);
            }}
          />
        </label>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-3">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}

      {result && (
        <div className="rounded-lg border border-green-200 bg-green-50 p-4 space-y-2">
          <p className="text-sm font-medium text-green-800">Onboarding successful</p>
          <div className="text-xs text-green-700 space-y-1">
            <p>
              Delegation ID: <span className="font-mono">{result.delegationId}</span>
            </p>
            <p>
              Issuer ID: <span className="font-mono">{result.issuerId}</span>
            </p>
            <p>Scope: {result.scope.join(", ")}</p>
            <p>
              Valid: {result.validFrom} — {result.validUntil}
            </p>
          </div>
          <div className="mt-2 rounded bg-green-100 p-2">
            <p className="text-xs text-green-800">
              Save your Delegation ID — you will need it for delegated credential issuance.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

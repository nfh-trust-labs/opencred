/**
 * JSON-LD context for the Education Credential (v1).
 *
 * Bundled inline — never fetched at runtime (see CLAUDE.md security rule 6).
 * Maps the credentialSubject fields to semantic terms under the OpenCred
 * namespace so JSON-LD processors can interpret the credential.
 */

export const educationV1Context: Record<string, unknown> = {
  "@context": {
    "@protected": true,
    EducationCredential:
      "https://opencred.org/ns/credentials/education#EducationCredential",
    recipientName: "https://opencred.org/ns/credentials/education#recipientName",
    degree: "https://opencred.org/ns/credentials/education#degree",
    institution: "https://opencred.org/ns/credentials/education#institution",
    dateConferred: {
      "@id": "https://opencred.org/ns/credentials/education#dateConferred",
      "@type": "http://www.w3.org/2001/XMLSchema#date",
    },
    fieldOfStudy: "https://opencred.org/ns/credentials/education#fieldOfStudy",
    honours: "https://opencred.org/ns/credentials/education#honours",
    gpa: {
      "@id": "https://opencred.org/ns/credentials/education#gpa",
      "@type": "http://www.w3.org/2001/XMLSchema#double",
    },
    accreditationBody:
      "https://opencred.org/ns/credentials/education#accreditationBody",
    programDuration:
      "https://opencred.org/ns/credentials/education#programDuration",
    credentialNumber:
      "https://opencred.org/ns/credentials/education#credentialNumber",
  },
};

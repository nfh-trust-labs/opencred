/**
 * IES MeterDataCredential Schema (v0.6) — bundled third-party schema.
 *
 * Upstream (canonical publication, also the schema's declared `$id`):
 * https://india-energy-stack.github.io/ies-accelerator/schemas/MeterDataCredential/v0.6/schema.json
 * Source repo: https://raw.githubusercontent.com/India-Energy-Stack/ies-accelerator/main/schemas/MeterDataCredential/v0.6/schema.json
 * (Verified byte-identical on 2026-06-13. Docs: https://india-energy-stack.gitbook.io/docs/schemas/meterdatacredential/v0.6 —
 * the context.json/vocab.json files that page references are not yet published
 * upstream (404), so no JSON-LD context is bundled for this credential yet.)
 *
 * The upstream document is embedded verbatim EXCEPT for the changes below,
 * applied at embed time so Ajv compiles the schema fully offline (security
 * invariant: NO remote fetches at validation/runtime):
 *
 *  - The envelope-level `allOf` `$ref` to schema.beckn.io/EnergyCredential/v2.0
 *    is dropped. It is not resolvable offline and contributes nothing to
 *    credentialSubject validation — the Validator extracts
 *    `properties.credentialSubject` (+ `$defs`) and discards envelope-level
 *    combinators anyway. VC envelope checks are handled by vc-core.
 *  - `credentialSubject.meterData` was a remote `$ref` to the MeterData/v0.6
 *    payload schema
 *    (https://raw.githubusercontent.com/India-Energy-Stack/ies-accelerator/main/schemas/MeterData/v0.6/schema.json)
 *    — the payload schema (fully self-contained upstream, no remote refs) is
 *    embedded inline: its `oneOf` entry point becomes `$defs/MeterData` and its
 *    `$defs` are merged into this schema's `$defs` (no name collisions).
 *  - All `x-jsonld` annotation keywords stripped: Ajv strict mode rejects
 *    unknown keywords.
 *  - `$defs/Interval.properties.payloads.items` used a union `type`
 *    (["number", "string", "boolean"]) which trips Ajv strictTypes; rewritten
 *    to the exactly equivalent `anyOf` form (the node had no other keywords).
 */

import { canonicalJsonSha256 } from "@opencred/shared";
import type { SchemaDefinition } from "../types.js";

export const iesMeterDataCredentialV0_6Schema: Record<string, unknown> = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://india-energy-stack.github.io/ies-accelerator/schemas/MeterDataCredential/v0.6/schema.json",
  title: "MeterDataCredential",
  description:
    "W3C Verifiable Credential wrapping a MeterData v0.6 payload. Subclass of EnergyCredential. Issued by a data provider (e.g., AMISP, MDM, DISCOM) to attest the authenticity and provenance of delivered smart meter telemetry.\n",
  type: "object",
  additionalProperties: true,
  properties: {
    credentialSubject: {
      $ref: "#/$defs/MeterDataCredentialSubject",
      description:
        "The subject of the credential: the consumer or asset entity whose meter data is attested, plus the MeterData payload.\n",
    },
  },
  $defs: {
    MeterDataCredentialSubject: {
      type: "object",
      description:
        "The subject of the credential: the consumer or asset entity whose meter data is attested.\n",
      required: ["meterData"],
      properties: {
        id: {
          type: "string",
          format: "uri",
          description: "DID of the consumer or asset entity whose meter data is being delivered.",
        },
        meterData: {
          $ref: "#/$defs/MeterData",
          description:
            "The attested meter data payload. May be a single EnergyData profile or an array of profiles per MeterData v0.6.\n",
        },
      },
    },
    MeterData: {
      title: "MeterData Payload",
      description: "Root payload can be a single profile or an array of profiles.",
      oneOf: [
        {
          $ref: "#/$defs/EnergyData",
        },
        {
          type: "array",
          minItems: 1,
          items: {
            $ref: "#/$defs/EnergyData",
          },
        },
      ],
    },
    EnergyData: {
      type: "object",
      title: "EnergyData",
      description:
        "A single compact data-only profile record. Must be one of the eight standard types.",
      oneOf: [
        {
          $ref: "#/$defs/PayloadDescriptorProfile",
        },
        {
          $ref: "#/$defs/CustomerProfile",
        },
        {
          $ref: "#/$defs/IntervalProfile",
        },
        {
          $ref: "#/$defs/DailyProfile",
        },
        {
          $ref: "#/$defs/MonthlyProfile",
        },
        {
          $ref: "#/$defs/BillDetails",
        },
        {
          $ref: "#/$defs/InstantaneousProfile",
        },
        {
          $ref: "#/$defs/EventProfile",
        },
        {
          $ref: "#/$defs/AlarmProfile",
        },
      ],
    },
    CustomerProfile: {
      type: "object",
      title: "CustomerProfile",
      description: "Slow-changing customer + service-point + meter-list summary.",
      required: ["profileType", "customer", "serviceDeliveryPoints", "meters", "associations"],
      properties: {
        profileType: {
          type: "string",
          const: "CUSTOMER",
        },
        customerRefs: {
          $ref: "#/$defs/IdentifierList",
        },
        timeZone: {
          type: "string",
          description: "IANA time-zone, e.g. Asia/Kolkata.",
        },
        customerDetails: {
          $ref: "#/$defs/CustomerDetails",
        },
        customer: {
          $ref: "#/$defs/Customer",
        },
        serviceDeliveryPoints: {
          type: "array",
          items: {
            $ref: "#/$defs/ServiceDeliveryPoint",
          },
        },
        meters: {
          type: "array",
          items: {
            $ref: "#/$defs/Meter",
          },
        },
        associations: {
          type: "array",
          items: {
            $ref: "#/$defs/Association",
          },
        },
      },
    },
    BaseProfile: {
      type: "object",
      description: "Root base profile carrying common identifiers across all shapes.",
      required: ["profileType", "meterRefs"],
      properties: {
        profileType: {
          type: "string",
        },
        customerRefs: {
          $ref: "#/$defs/IdentifierList",
        },
        meterRefs: {
          $ref: "#/$defs/IdentifierList",
        },
        serviceDeliveryPointRefs: {
          $ref: "#/$defs/IdentifierList",
        },
        payloadDescriptorSetRef: {
          type: "string",
          description:
            "Reference ID matching a previously exchanged PayloadDescriptorProfile's payloadDescriptorSet.",
        },
      },
    },
    IntervalProfile: {
      type: "object",
      title: "IntervalProfile",
      description: "Block Load Survey — PT15M / PT30M cadence intervalBlocks for one meter.",
      allOf: [
        {
          $ref: "#/$defs/BaseProfile",
        },
        {
          type: "object",
          required: ["intervalPeriod"],
          properties: {
            profileType: {
              type: "string",
              const: "INTERVAL",
            },
            compactSequenceRef: {
              type: "string",
              description: "Name of the compact sequence to use from the payloadDescriptorSets.",
            },
            intervalPeriod: {
              $ref: "#/$defs/IntervalPeriod",
            },
            intervals: {
              type: "array",
              items: {
                $ref: "#/$defs/Interval",
              },
            },
            readings: {
              type: "array",
              items: {
                $ref: "#/$defs/Reading",
              },
            },
          },
        },
      ],
    },
    DailyProfile: {
      type: "object",
      title: "DailyProfile",
      description:
        "Daily Load Profile — P1D intervalBlocks. Same per-meter shape as IntervalProfile.",
      allOf: [
        {
          $ref: "#/$defs/BaseProfile",
        },
        {
          type: "object",
          required: ["intervalPeriod"],
          properties: {
            profileType: {
              type: "string",
              const: "DAILY",
            },
            compactSequenceRef: {
              type: "string",
              description: "Name of the compact sequence to use from the payloadDescriptorSets.",
            },
            intervalPeriod: {
              $ref: "#/$defs/IntervalPeriod",
            },
            intervals: {
              type: "array",
              items: {
                $ref: "#/$defs/Interval",
              },
            },
            readings: {
              type: "array",
              items: {
                $ref: "#/$defs/Reading",
              },
            },
          },
        },
      ],
    },
    MonthlyProfile: {
      type: "object",
      title: "MonthlyProfile",
      description:
        "Monthly profile readings from the meter at billing reset time (billing history).",
      allOf: [
        {
          $ref: "#/$defs/BaseProfile",
        },
        {
          type: "object",
          required: ["timePeriod", "readings"],
          properties: {
            profileType: {
              type: "string",
              const: "MONTHLY",
            },
            timePeriod: {
              $ref: "#/$defs/TimePeriod",
            },
            readings: {
              type: "array",
              items: {
                $ref: "#/$defs/Reading",
              },
            },
            touBuckets: {
              type: "array",
              items: {
                $ref: "#/$defs/TouBucket",
              },
            },
          },
        },
      ],
    },
    BillDetails: {
      type: "object",
      title: "BillDetails",
      description:
        "Utility billing computed details, such as billing amount, bill number, due dates, and prepaid balance.",
      allOf: [
        {
          $ref: "#/$defs/BaseProfile",
        },
        {
          type: "object",
          required: ["timePeriod", "amountDue"],
          properties: {
            profileType: {
              type: "string",
              const: "BILL_DETAILS",
            },
            timePeriod: {
              $ref: "#/$defs/TimePeriod",
            },
            readings: {
              type: "array",
              items: {
                $ref: "#/$defs/Reading",
              },
            },
            touBuckets: {
              type: "array",
              items: {
                $ref: "#/$defs/TouBucket",
              },
            },
            billNumber: {
              type: "string",
            },
            billDate: {
              type: "string",
              format: "date",
            },
            dueDate: {
              type: "string",
              format: "date",
            },
            currency: {
              type: "string",
              description: "ISO 4217 (INR, USD, ...).",
            },
            amountDue: {
              type: "number",
            },
            energyCharges: {
              type: "number",
              description: "Charges for active/reactive energy consumption.",
            },
            fixedCharges: {
              type: "number",
              description: "Fixed charges/demand charges.",
            },
            otherCharges: {
              type: "number",
              description: "Other taxes, duties, surcharges, or adjustments.",
            },
            prepaidBalance: {
              type: "number",
              description:
                "Prepaid remaining balance/credit amount on the account/meter, if applicable.",
            },
            paymentStatus: {
              type: "string",
              description: "Status of the payment, e.g. PAID, UNPAID, PARTIAL.",
            },
          },
        },
      ],
    },
    InstantaneousProfile: {
      type: "object",
      title: "InstantaneousProfile",
      description: "Snapshot of a meter's electrical quantities at one captured moment.",
      allOf: [
        {
          $ref: "#/$defs/BaseProfile",
        },
        {
          type: "object",
          required: ["timestamp", "readings"],
          properties: {
            profileType: {
              type: "string",
              const: "INSTANTANEOUS",
            },
            timestamp: {
              type: "string",
              format: "date-time",
            },
            readings: {
              type: "array",
              items: {
                $ref: "#/$defs/Reading",
              },
            },
          },
        },
      ],
    },
    AlarmProfile: {
      type: "object",
      title: "AlarmProfile",
      description:
        "Real-time active indicators/alerts representing immediate state conditions from the meter.",
      allOf: [
        {
          $ref: "#/$defs/BaseProfile",
        },
        {
          type: "object",
          required: ["timestamp", "alarms"],
          properties: {
            profileType: {
              type: "string",
              const: "ALARM",
            },
            timestamp: {
              type: "string",
              format: "date-time",
            },
            alarms: {
              type: "array",
              items: {
                $ref: "#/$defs/MeterAlarm",
              },
            },
          },
        },
      ],
    },
    EventProfile: {
      type: "object",
      title: "EventProfile",
      description: "IS 15959 event log for one meter over a coverage period.",
      allOf: [
        {
          $ref: "#/$defs/BaseProfile",
        },
        {
          type: "object",
          required: ["timePeriod", "events"],
          properties: {
            profileType: {
              type: "string",
              const: "EVENT",
            },
            timePeriod: {
              $ref: "#/$defs/TimePeriod",
            },
            events: {
              type: "array",
              items: {
                $ref: "#/$defs/MeterEvent",
              },
            },
          },
        },
      ],
    },
    Identifier: {
      type: "object",
      title: "Identifier",
      description:
        "Canonical {scheme, value} reference. Used for customer/meter/SDP/OBIS references.",
      required: ["scheme", "value"],
      properties: {
        scheme: {
          $ref: "#/$defs/IdentifierScheme",
        },
        value: {
          type: "string",
        },
        namespace: {
          type: "string",
        },
      },
    },
    IdentifierList: {
      type: "array",
      title: "IdentifierList",
      description:
        "Non-empty list of Identifiers for the same underlying entity. First element is the primary; additional elements are alternates under different schemes.",
      minItems: 1,
      items: {
        $ref: "#/$defs/Identifier",
      },
    },
    TimePeriod: {
      type: "object",
      description: "Period defined by a start time and a duration.",
      required: ["start", "duration"],
      properties: {
        start: {
          type: "string",
          format: "date-time",
        },
        duration: {
          type: "string",
          format: "duration",
        },
      },
    },
    TelemetryMode: {
      type: "string",
      enum: ["READING", "USAGE"],
    },
    ReadingDefinition: {
      type: "object",
      required: ["readingType", "supportedModes", "defaultMode"],
      properties: {
        readingType: {
          type: "string",
        },
        supportedModes: {
          type: "array",
          minItems: 1,
          items: {
            $ref: "#/$defs/TelemetryMode",
          },
        },
        defaultMode: {
          $ref: "#/$defs/TelemetryMode",
        },
        name: {
          type: "string",
        },
        shortLabel: {
          type: "string",
        },
        unit: {
          $ref: "#/$defs/UnitOfMeasure",
        },
        phase: {
          $ref: "#/$defs/Phase",
        },
        flowDirection: {
          type: "string",
          enum: ["IMPORT", "EXPORT", "NONE"],
        },
        accumulationBehaviour: {
          $ref: "#/$defs/AccumulationBehaviour",
        },
        touZone: {
          type: "integer",
          minimum: 0,
          maximum: 8,
        },
      },
    },
    PayloadDescriptorSet: {
      type: "object",
      required: ["name", "payloadDescriptors"],
      properties: {
        name: {
          type: "string",
        },
        payloadDescriptors: {
          type: "array",
          items: {
            $ref: "#/$defs/PayloadDescriptor",
          },
        },
        compactSequences: {
          type: "array",
          items: {
            $ref: "#/$defs/CompactSequence",
          },
        },
      },
    },
    CompactSequence: {
      type: "object",
      required: ["name", "sequenceItems"],
      properties: {
        name: {
          type: "string",
        },
        sequenceItems: {
          type: "array",
          items: {
            $ref: "#/$defs/SequenceItem",
          },
        },
      },
    },
    SequenceItem: {
      type: "object",
      required: ["readingType"],
      properties: {
        readingType: {
          type: "string",
        },
        attribute: {
          type: "string",
          enum: ["value", "occurredAt", "openingValue", "closingValue", "validationStatus"],
          default: "value",
        },
      },
    },
    PayloadDescriptor: {
      type: "object",
      description:
        "One quantity declared once per block; rows' values[] align positionally with descriptors[].",
      required: ["readingType"],
      properties: {
        readingType: {
          type: "string",
        },
        obis: {
          type: "string",
          description: "Optional canonical OBIS code when readingType uses a short code.",
        },
        name: {
          type: "string",
        },
        unit: {
          $ref: "#/$defs/UnitOfMeasure",
        },
        flowDirection: {
          type: "string",
          enum: ["IMPORT", "EXPORT", "NONE"],
        },
        category: {
          type: "string",
        },
        reportedMode: {
          $ref: "#/$defs/TelemetryMode",
        },
        touZone: {
          type: "integer",
          minimum: 0,
          maximum: 8,
        },
        multiplier: {
          type: "number",
          description:
            "Decimal scaling factor (e.g. 0.001 for milli, 1000 for kilo). Default value is 1.",
          default: 1,
        },
        accuracy: {
          type: "number",
          description: "Accuracy class or precision value, applied after the multiplier.",
        },
      },
    },
    IntervalPeriod: {
      type: "object",
      description: "Period defined by a start time and a duration.",
      required: ["start", "duration"],
      properties: {
        start: {
          type: "string",
          format: "date-time",
        },
        duration: {
          type: "string",
          format: "duration",
        },
      },
    },
    Interval: {
      type: "object",
      description: "One time-series interval row. payloads[k] is the value for compactSequence[k].",
      required: ["id"],
      properties: {
        id: {
          type: "integer",
          minimum: 0,
        },
        intervalPeriod: {
          $ref: "#/$defs/IntervalPeriod",
        },
        payloads: {
          type: "array",
          minItems: 1,
          items: {
            anyOf: [
              {
                type: "number",
              },
              {
                type: "string",
              },
              {
                type: "boolean",
              },
            ],
          },
        },
        readings: {
          type: "array",
          items: {
            $ref: "#/$defs/Reading",
          },
        },
        overrides: {
          type: "array",
          items: {
            $ref: "#/$defs/Override",
          },
        },
      },
    },
    Override: {
      type: "object",
      description:
        "Sparse — inject timestamps, zones, or validation states into specific interval cells.",
      required: ["descriptorIndex"],
      properties: {
        descriptorIndex: {
          type: "integer",
          minimum: 0,
        },
        occurredAt: {
          type: "string",
          format: "date-time",
        },
        zone: {
          type: "integer",
          minimum: 1,
          maximum: 8,
        },
        validationStatus: {
          $ref: "#/$defs/ValidationStatus",
        },
        source: {
          $ref: "#/$defs/ReadingSource",
        },
        changeMethod: {
          type: "string",
        },
        failCode: {
          type: "string",
        },
      },
    },
    Reading: {
      type: "object",
      description: "Detailed, self-contained inline reading with full metadata support.",
      required: ["readingType", "value"],
      properties: {
        readingType: {
          type: "string",
        },
        value: {
          type: "number",
        },
        openingValue: {
          type: "number",
          description:
            "MUST ONLY be provided when the associated payload descriptor specifies reportedMode=USAGE.",
        },
        closingValue: {
          type: "number",
          description:
            "MUST ONLY be provided when the associated payload descriptor specifies reportedMode=USAGE.",
        },
        integrationPeriod: {
          type: "string",
          format: "duration",
          description: "Demand integration period, e.g. PT30M or PT15M.",
        },
        timePeriod: {
          $ref: "#/$defs/TimePeriod",
        },
        occurredAt: {
          type: "string",
          format: "date-time",
        },
        validationStatus: {
          $ref: "#/$defs/ValidationStatus",
        },
        source: {
          $ref: "#/$defs/ReadingSource",
        },
        changeMethod: {
          type: "string",
        },
        failCode: {
          type: "string",
        },
      },
    },
    TouBucket: {
      type: "object",
      description: "Time of Use bucket separating readings by zone.",
      required: ["zone", "readings"],
      properties: {
        zone: {
          type: "integer",
          minimum: 1,
          maximum: 8,
        },
        readings: {
          type: "array",
          items: {
            $ref: "#/$defs/Reading",
          },
        },
      },
    },
    Customer: {
      type: "object",
      required: ["id"],
      properties: {
        id: {
          $ref: "#/$defs/Identifier",
        },
        name: {
          type: "string",
        },
        consumerCategory: {
          type: "string",
          description: "Utility tariff category (e.g., LT2A, NDS, HT).",
        },
        sanctionedLoadKw: {
          type: "number",
          minimum: 0,
        },
        billingCycleDay: {
          type: "integer",
          minimum: 1,
          maximum: 31,
        },
        paymentMode: {
          type: "string",
          enum: ["PREPAID", "POSTPAID"],
          description: "Indicates if the connection is prepaid or postpaid.",
        },
        connectionType: {
          type: "string",
          enum: ["Single-phase", "Three-phase"],
          description: "Type of connection (Single-phase or Three-phase).",
        },
        contractMaxDemandKw: {
          type: "number",
          minimum: 0,
          description: "Maximum demand contracted with the utility for this connection, in kW.",
        },
        tariffCategoryCode: {
          type: "string",
          description: "Billing/tariff category code assigned by the utility.",
        },
        sanctionedExportLoadKw: {
          type: "number",
          minimum: 0,
          description: "Sanctioned/approved grid export limit in kW.",
        },
      },
    },
    CustomerDetails: {
      type: "object",
      description: "PII sub-object. Omit entirely for anonymised or pseudonymous exchange.",
      properties: {
        name: {
          type: "string",
          description: "Full name of the customer as per ID proof.",
        },
      },
    },
    ServiceDeliveryPoint: {
      type: "object",
      required: ["id"],
      properties: {
        id: {
          $ref: "#/$defs/Identifier",
        },
        address: {
          $ref: "#/$defs/Address",
        },
        geo: {
          $ref: "#/$defs/GeoJSONGeometry",
        },
      },
    },
    Meter: {
      type: "object",
      required: ["id"],
      properties: {
        id: {
          $ref: "#/$defs/Identifier",
        },
        make: {
          type: "string",
          description: "Make of the meter.",
        },
        model: {
          type: "string",
          description: "Model of the meter.",
        },
        meterType: {
          $ref: "#/$defs/MeterType",
        },
        meterCategory: {
          $ref: "#/$defs/MeterCategory",
        },
        serviceKind: {
          $ref: "#/$defs/ServiceKind",
        },
      },
    },
    Association: {
      type: "object",
      required: ["serviceDeliveryPointRefs", "meterRefs"],
      properties: {
        serviceDeliveryPointRefs: {
          $ref: "#/$defs/IdentifierList",
        },
        meterRefs: {
          $ref: "#/$defs/IdentifierList",
        },
        parentResources: {
          type: "array",
          items: {
            $ref: "#/$defs/Identifier",
          },
          description:
            "List of parent resources (such as feeders or DTs) for this association, replacing feederId and dtId.",
        },
        telemetryProvider: {
          type: "string",
          description: "Telemetry provider for this meter-service association.",
        },
        commissioningDate: {
          type: "string",
          format: "date-time",
          description: "Commissioning date of the meter association.",
        },
        generationCapacityKw: {
          type: "number",
          minimum: 0,
          description: "Rated power generation capacity (e.g. solar PV inverter capacity) in kW.",
        },
        storageCapacityKw: {
          type: "number",
          minimum: 0,
          description: "Rated energy storage capacity in kWh.",
        },
      },
    },
    MeterEvent: {
      type: "object",
      required: ["timestamp", "eventId"],
      properties: {
        timestamp: {
          type: "string",
          format: "date-time",
        },
        eventId: {
          type: "integer",
          minimum: 1,
        },
        eventName: {
          type: "string",
        },
        phase: {
          $ref: "#/$defs/Phase",
        },
        sequence: {
          type: "integer",
          minimum: 0,
        },
        magnitude: {
          type: "number",
        },
        duration: {
          type: "string",
          format: "duration",
        },
      },
    },
    MeterAlarm: {
      type: "object",
      required: ["timestamp", "alarmId", "status"],
      properties: {
        timestamp: {
          type: "string",
          format: "date-time",
        },
        alarmId: {
          type: "integer",
          minimum: 1,
        },
        alarmName: {
          type: "string",
        },
        status: {
          type: "string",
          enum: ["ACTIVE", "CLEARED"],
        },
        severity: {
          type: "string",
          enum: ["CRITICAL", "WARNING", "INFO"],
        },
      },
    },
    IdentifierScheme: {
      type: "string",
      enum: [
        "METER_SERIAL",
        "METER_BADGE",
        "MRID",
        "OBIS",
        "SHORT_CODE",
        "CONSUMER_NUMBER",
        "SERVICE_DELIVERY_POINT",
        "DID",
        "ORG",
        "OTHER",
      ],
    },
    Phase: {
      type: "string",
      enum: ["NONE", "R", "Y", "B", "ABC"],
    },
    UnitOfMeasure: {
      type: "string",
      enum: [
        "kWh",
        "kVAh",
        "kvarh",
        "kW",
        "kvar",
        "kVA",
        "V",
        "A",
        "Hz",
        "PF",
        "NONE",
        "INR",
        "USD",
      ],
    },
    AccumulationBehaviour: {
      type: "string",
      enum: ["CUMULATIVE", "DELTA", "INSTANTANEOUS", "SUMMATION", "INDICATING"],
    },
    ValidationStatus: {
      type: "string",
      enum: ["VALID", "ESTIMATED", "MANUAL", "SUSPECT", "REJECTED"],
    },
    ReadingSource: {
      type: "string",
      enum: ["METER", "HES", "ESTIMATED", "MANUAL", "IMPORT", "MDM_COMPUTED", "CIS_COMPUTED"],
    },
    MeterCategory: {
      type: "string",
      enum: ["A", "B", "C", "D1", "D2", "D3", "D4"],
    },
    ServiceKind: {
      type: "string",
      enum: ["ELECTRICITY", "GAS", "WATER", "HEAT"],
    },
    PayloadDescriptorProfile: {
      type: "object",
      title: "PayloadDescriptorProfile",
      description:
        "Configuration profile representing a collection of Payload Descriptor Sets exchanged out-of-band or embedded in an array.",
      required: ["profileType", "id", "payloadDescriptorSets"],
      properties: {
        profileType: {
          type: "string",
          const: "DESCRIPTOR",
        },
        id: {
          type: "string",
          description: "Unique identifier for this specific configuration state.",
        },
        payloadDescriptorSets: {
          type: "array",
          items: {
            $ref: "#/$defs/PayloadDescriptorSet",
          },
        },
      },
    },
    MeterType: {
      type: "string",
      description: "Type of electricity meter. Shared with ElectricityCredential schema.",
      enum: [
        "AMR",
        "AMI",
        "Electromechanical",
        "Forward",
        "Reverse",
        "Bidirectional",
        "Prepaid",
        "NetMeter",
        "Other",
      ],
    },
    Address: {
      type: "object",
      description:
        "Postal address per beckn Address/v2.0 and schema.org PostalAddress. All fields optional.",
      properties: {
        streetAddress: {
          type: "string",
          description: "Building name/number and street.",
        },
        extendedAddress: {
          type: "string",
          description: "Apt, suite, floor, or C/O.",
        },
        addressLocality: {
          type: "string",
          description: "City or locality.",
        },
        addressRegion: {
          type: "string",
          description: "State, region or province.",
        },
        addressCountry: {
          type: "string",
          pattern: "^[A-Z]{2}$",
          description: "ISO 3166-1 alpha-2 country code.",
        },
        postalCode: {
          type: "string",
          description: "Postal or ZIP code.",
        },
      },
      additionalProperties: false,
    },
    GeoJSONGeometry: {
      type: "object",
      description:
        "GeoJSON geometry per RFC 7946 / beckn GeoJSONGeometry/v2.0. Coordinates are [longitude, latitude, (altitude?)] in EPSG:4326 (WGS-84). For a point: {type: 'Point', coordinates: [lon, lat]}.",
      required: ["type"],
      properties: {
        type: {
          type: "string",
          enum: [
            "Point",
            "LineString",
            "Polygon",
            "MultiPoint",
            "MultiLineString",
            "MultiPolygon",
            "GeometryCollection",
          ],
        },
        coordinates: {
          type: "array",
          description: "Coordinates per RFC 7946. For a Point: [longitude, latitude].",
        },
        geometries: {
          type: "array",
          items: {
            $ref: "#/$defs/GeoJSONGeometry",
          },
          description: "Member geometries when type is GeometryCollection.",
        },
        bbox: {
          type: "array",
          minItems: 4,
          maxItems: 4,
          items: {
            type: "number",
          },
          description: "Bounding box [west, south, east, north] in degrees.",
        },
      },
      additionalProperties: true,
    },
  },
};

const iesMeterDataCredentialV0_6Checksum = canonicalJsonSha256(iesMeterDataCredentialV0_6Schema);

export const iesMeterDataCredentialV0_6Definition: SchemaDefinition = {
  id: "ies/meter-data-credential/v0.6",
  schema: iesMeterDataCredentialV0_6Schema,
  version: "0.6.0",
  lastUpdated: "2026-06-12T00:00:00Z",
  checksum: iesMeterDataCredentialV0_6Checksum,
  source: {
    kind: "referenced",
    upstreamUrl:
      "https://india-energy-stack.github.io/ies-accelerator/schemas/MeterDataCredential/v0.6/schema.json",
    upstreamOwner: "India Energy Stack",
    upstreamLicense: "MIT",
  },
  category: "utility",
};

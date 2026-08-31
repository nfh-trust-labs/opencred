/**
 * IES ElectricityCredential Schema (v1.2) — bundled third-party schema.
 *
 * Upstream (canonical publication): https://schema.beckn.io/ElectricityCredential/1.2/schema.json
 * Source repo: https://raw.githubusercontent.com/India-Energy-Stack/ies-accelerator/main/schemas/ElectricityCredential/v1.2/schema.json
 * (Verified byte-identical on 2026-06-13.)
 *
 * The upstream document is embedded verbatim EXCEPT for the changes below,
 * applied at embed time so Ajv compiles the schema fully offline (security
 * invariant: NO remote fetches at validation/runtime):
 *
 *  - `$defs/ConsumptionProfile` was a remote `$ref` to
 *    schema.beckn.io/MeterServiceProfile/v1.1#MeterServiceProfile — replaced
 *    with the inlined beckn definition. Its `#/$defs/QVPower` refs resolve to
 *    the structurally identical QVPower def already bundled in this schema.
 *  - `$defs/CustomerDetails` was a remote `$ref` to
 *    schema.beckn.io/CustomerDetails/v1.0#CustomerDetails — replaced with the
 *    inlined beckn definition; its `installationAddress` ref to beckn
 *    Location/2.0 is rewritten to the equivalent local `#/$defs/Location`
 *    (geo: GeoJSON required, address optional — same shape).
 *  - All `$anchor` keywords stripped: Ajv strict mode rejects unknown keywords
 *    under its default draft-07 dialect, and every `$ref` in the bundled form
 *    uses JSON-pointer syntax so the anchors are unused.
 */

import { canonicalJsonSha256 } from "@opencred/shared";
import type { SchemaDefinition } from "../types.js";

export const iesElectricityCredentialV1_2Schema: Record<string, unknown> = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://github.com/beckn/DEG/blob/main/specification/schema/ElectricityCredential/v1.2/schema.json",
  title: "ElectricityCredential v1.2",
  description:
    "Bundled (self-contained) JSON Schema for ElectricityCredential v1.2. All power and capacity fields use QuantitativeValue {value, unit} with short unit aliases (W, kW, MW, kWh, MWh, kVA, MVA, kVAR, MVAR, V, kV) mapped to QUDT IRIs via JSON-LD context. Renamed from v1.1: ratedPowerKw→ratedPower, maxExportKw→maxExport, maxImportKw→maxImport, nominalPowerKw→nominalPower, storageCapacityKwh→storageCapacity, ratedApparentPowerKva→ratedApparentPower, maxReactivePowerKvar→maxReactivePower, minReactivePowerKvar→minReactivePower, nominalVoltageKv→nominalVoltage, sanctionedLoadKw→sanctionedLoad, contractMaxDemandKw→contractMaxDemand. Subschemas: EnergyResource/v2.1, EnergyResourceCommon/v1.1, MeterServiceProfile/v1.1.",
  type: "object",
  required: ["@context", "id", "type", "issuer", "validFrom", "credentialSubject"],
  properties: {
    "@context": {
      type: "array",
      items: {
        type: "string",
      },
      contains: {
        const: "https://www.w3.org/ns/credentials/v2",
      },
      minItems: 2,
    },
    id: {
      type: "string",
      format: "uri",
      pattern: "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    },
    type: {
      type: "array",
      items: {
        type: "string",
      },
      contains: {
        const: "ElectricityCredential",
      },
      minItems: 2,
    },
    issuer: {
      type: "object",
      required: ["id", "name"],
      properties: {
        id: {
          type: "string",
          format: "uri",
        },
        name: {
          type: "string",
          minLength: 1,
        },
        idRef: {
          $ref: "#/$defs/IdRef",
        },
      },
    },
    validFrom: {
      type: "string",
      format: "date-time",
    },
    validUntil: {
      type: "string",
      format: "date-time",
    },
    credentialStatus: {
      type: "object",
      required: ["id", "type", "statusPurpose", "statusListCredential"],
      properties: {
        id: {
          type: "string",
          format: "uri",
        },
        type: {
          type: "string",
          const: "dediregistry",
        },
        statusPurpose: {
          type: "string",
          enum: ["revocation", "suspension"],
        },
        statusListCredential: {
          type: "string",
          format: "uri",
        },
      },
    },
    credentialSubject: {
      type: "object",
      required: ["customerProfile"],
      properties: {
        id: {
          type: "string",
          format: "uri",
        },
        customerProfile: {
          $ref: "#/$defs/CustomerProfile",
        },
        customerDetails: {
          $ref: "#/$defs/CustomerDetails",
        },
      },
    },
    proof: {
      type: "object",
      required: ["type", "created", "verificationMethod", "proofPurpose", "proofValue"],
      properties: {
        type: {
          type: "string",
        },
        created: {
          type: "string",
          format: "date-time",
        },
        verificationMethod: {
          type: "string",
          format: "uri",
        },
        proofPurpose: {
          type: "string",
          enum: ["assertionMethod", "authentication"],
        },
        proofValue: {
          type: "string",
          minLength: 1,
        },
      },
    },
  },
  $defs: {
    QVPower: {
      type: "object",
      description:
        "Active power quantity. unit: W | kW | MW — mapped to QUDT IRIs via JSON-LD context.",
      required: ["value", "unit"],
      additionalProperties: false,
      properties: {
        value: {
          type: "number",
        },
        unit: {
          type: "string",
          enum: ["W", "kW", "MW"],
        },
      },
    },
    QVEnergy: {
      type: "object",
      description: "Stored-energy quantity. unit: kWh | MWh.",
      required: ["value", "unit"],
      additionalProperties: false,
      properties: {
        value: {
          type: "number",
          minimum: 0,
        },
        unit: {
          type: "string",
          enum: ["kWh", "MWh"],
        },
      },
    },
    QVApparentPower: {
      type: "object",
      description: "Apparent power quantity. unit: kVA | MVA.",
      required: ["value", "unit"],
      additionalProperties: false,
      properties: {
        value: {
          type: "number",
          minimum: 0,
        },
        unit: {
          type: "string",
          enum: ["kVA", "MVA"],
        },
      },
    },
    QVReactivePower: {
      type: "object",
      description:
        "Reactive power quantity. unit: kVAR | MVAR. Value may be negative for absorption.",
      required: ["value", "unit"],
      additionalProperties: false,
      properties: {
        value: {
          type: "number",
        },
        unit: {
          type: "string",
          enum: ["kVAR", "MVAR"],
        },
      },
    },
    QVVoltage: {
      type: "object",
      description: "Voltage quantity. unit: V | kV.",
      required: ["value", "unit"],
      additionalProperties: false,
      properties: {
        value: {
          type: "number",
          minimum: 0,
        },
        unit: {
          type: "string",
          enum: ["V", "kV"],
        },
      },
    },
    IdRef: {
      type: "object",
      required: ["issuedBy", "subjectId"],
      properties: {
        issuedBy: {
          type: "string",
          format: "uri",
        },
        subjectId: {
          type: "string",
          pattern: "^[A-Za-z0-9._-]+:[A-Za-z0-9X_-]+$",
        },
      },
    },
    CustomerProfile: {
      type: "object",
      description: "Non-PII customer identity, physical assets, and tariff profiles.",
      required: ["customerNumber", "energyResources"],
      properties: {
        customerNumber: {
          type: "string",
          minLength: 1,
        },
        idRef: {
          $ref: "#/$defs/IdRef",
        },
        energyResources: {
          type: "array",
          minItems: 1,
          items: {
            $ref: "#/$defs/EnergyResource",
          },
        },
        consumptionProfiles: {
          type: "array",
          minItems: 1,
          items: {
            $ref: "#/$defs/ConsumptionProfile",
          },
        },
      },
    },
    ConsumptionProfile: {
      type: "object",
      description:
        "Tariff and regulatory load profile for one meter connection. meterId matches the id of a METER entry in energyResources[].",
      required: ["meterId", "sanctionedLoad", "tariffCategoryCode"],
      properties: {
        meterId: {
          type: "string",
          minLength: 1,
          description: "Matches the id of a METER entry in customerProfile.energyResources[].",
        },
        sanctionedLoad: {
          $ref: "#/$defs/QVPower",
          description:
            "Sanctioned/approved import load. unit: W | kW | MW. CIM: UsagePoint.ratedCurrent × voltage.",
        },
        sanctionedExportLoad: {
          $ref: "#/$defs/QVPower",
          description: "Sanctioned/approved grid export limit. unit: W | kW | MW.",
        },
        billingCycleDay: {
          type: "integer",
          minimum: 1,
          maximum: 31,
          description: "Day of month the billing cycle resets.",
        },
        contractMaxDemand: {
          $ref: "#/$defs/QVPower",
          description: "Maximum demand contracted with the utility. unit: W | kW | MW.",
        },
        tariffCategoryCode: {
          type: "string",
          minLength: 1,
          description: "Billing/tariff category code assigned by the utility.",
        },
        premisesType: {
          type: "string",
          enum: ["Residential", "Commercial", "Industrial", "Agricultural"],
        },
        connectionType: {
          type: "string",
          enum: ["Single-phase", "Three-phase"],
          description: "Electrical connection type. CIM: UsagePoint.phaseCode.",
        },
        paymentMode: {
          type: "string",
          enum: ["POSTPAID", "PREPAID"],
          description:
            "Billing/payment modality. Administrative — placed on the profile not the meter. CIM: ESPI AmiBillingReadyKind.",
        },
      },
    },
    CustomerDetails: {
      type: "object",
      required: ["fullName", "installationAddress", "serviceConnectionDate"],
      properties: {
        fullName: {
          type: "string",
          minLength: 1,
          maxLength: 200,
          description: "Full name of the customer as per ID proof.",
        },
        installationAddress: {
          $ref: "#/$defs/Location",
          description:
            "Physical location of the metered installation. geo (GeoJSON Point) required; address (PostalAddress) optional.",
        },
        serviceConnectionDate: {
          type: "string",
          format: "date-time",
          description:
            "Date and time the service connection was activated (ISO 8601 with timezone offset).",
        },
      },
    },
    EnergyResourceCommonAttributes: {
      type: "object",
      description:
        "Base attributes shared by all EnergyResource kinds. ratedPower, maxExport, maxImport are QVPower {value, unit: W|kW|MW}.",
      additionalProperties: true,
      properties: {
        make: {
          type: "string",
          description: "Manufacturer name.",
        },
        model: {
          type: "string",
          description: "Model number or name.",
        },
        ratedPower: {
          description:
            "Manufacturer-rated power. unit: W | kW | MW. CIM: GeneratingUnit.maxOperatingP / EndDeviceInfo.ratedPower.",
          $ref: "#/$defs/QVPower",
        },
        maxImport: {
          description:
            "Maximum power drawn from the grid (absorbs/charges). unit: W | kW | MW. Always ≥0. CIM: PowerElectronicsConnection.maxP (absorption direction).",
          $ref: "#/$defs/QVPower",
        },
        maxExport: {
          description:
            "Maximum power injected to the grid (generates/discharges). unit: W | kW | MW. Always ≥0. CIM: GeneratingUnit.maxOperatingP / PowerElectronicsConnection.maxP (injection direction).",
          $ref: "#/$defs/QVPower",
        },
        telemetryProvider: {
          type: "string",
          description: "Vendor API or data-source identifier for telemetry.",
        },
        commissioningDate: {
          type: "string",
          format: "date-time",
          description: "ISO 8601 date-time the asset was commissioned.",
        },
        location: {
          $ref: "#/$defs/Location",
        },
      },
    },
    EnergyResourceMeterAttributes: {
      description:
        "Attributes for metering devices (type: METER). CIM: Meter extends EndDevice (IEC 61968-9).",
      allOf: [
        {
          $ref: "#/$defs/EnergyResourceCommonAttributes",
        },
        {
          type: "object",
          properties: {
            meterCapability: {
              type: "string",
              enum: ["Electromechanical", "CMRI", "AMR", "AMI"],
              description:
                "Communication/automation generation. CIM: AmiBillingReadyKind (IEC 61968-9).",
            },
            energyDirection: {
              type: "string",
              enum: ["Forward", "Reverse", "Bidirectional", "Net"],
              default: "Forward",
              description: "Energy flow direction. CIM: FlowDirectionKind (ESPI NAESB REQ.21).",
            },
            functions: {
              type: "array",
              uniqueItems: true,
              description: "Active meter capabilities per IEC 61968-9 EndDeviceFunction.",
              items: {
                type: "string",
                enum: [
                  "ToU",
                  "NetMetering",
                  "MaxDemand",
                  "LoadControl",
                  "TamperDetection",
                  "PowerQuality",
                  "EventLogging",
                ],
              },
            },
            feeder: {
              type: "string",
              description: "Feeder identifier this meter is supplied from.",
            },
            bus: {
              type: "string",
              description: "Busbar identifier.",
            },
            communicationTechnology: {
              type: "string",
              enum: ["PLC", "RF_Mesh", "GPRS", "NB-IoT", "LoRa", "ZigBee", "Other"],
            },
            applicationProtocol: {
              type: "string",
              enum: ["DLMS_COSEM", "ANSI_C12_18", "IEC_61850", "Modbus", "Other"],
            },
          },
        },
      ],
    },
    EnergyResourceGeneratorAttributes: {
      description:
        "Attributes for generation assets. CIM: GeneratingUnit subtypes (IEC 61970-302).",
      allOf: [
        {
          $ref: "#/$defs/EnergyResourceCommonAttributes",
        },
        {
          type: "object",
          properties: {
            nominalPower: {
              description:
                "Nominal (nameplate) power output. unit: W | kW | MW. CIM: GeneratingUnit.nominalP.",
              $ref: "#/$defs/QVPower",
            },
            efficiency: {
              type: "number",
              minimum: 0,
              maximum: 100,
              description: "Conversion efficiency in percent. Relevant for FUEL_CELL and CHP.",
            },
          },
        },
      ],
    },
    EnergyResourceStorageAttributes: {
      description:
        "Attributes for stationary energy storage assets (BESS). CIM: BatteryUnit (IEC 61970-302).",
      allOf: [
        {
          $ref: "#/$defs/EnergyResourceCommonAttributes",
        },
        {
          type: "object",
          properties: {
            storageCapacity: {
              description:
                "Rated stored-energy capacity. unit: kWh | MWh. CIM: BatteryUnit.ratedE.",
              $ref: "#/$defs/QVEnergy",
            },
            storageType: {
              type: "string",
              enum: ["LithiumIon", "LeadAcid", "FlowBattery", "NaS", "NiCd", "Flywheel", "Other"],
            },
            stateOfHealthPct: {
              type: "number",
              minimum: 0,
              maximum: 100,
              description: "Battery state of health as percentage of original capacity.",
            },
          },
        },
      ],
    },
    EnergyResourceEVChargerAttributes: {
      description:
        "Attributes for EV charging stations. EV_CHARGER is a flexible load at the grid connection point. EV_V2G adds ISO 15118-20 / OCPP 2.1 BPT bidirectional capability. CIM: ElectricVehicleChargingStation (CIM17+).",
      allOf: [
        {
          $ref: "#/$defs/EnergyResourceCommonAttributes",
        },
        {
          type: "object",
          properties: {
            connectorType: {
              type: "string",
              enum: ["Type1", "Type2", "CCS1", "CCS2", "CHAdeMO", "GB_T", "NACS", "Other"],
            },
            controlProtocol: {
              type: "string",
              enum: ["OCPP_1.6", "OCPP_2.0.1", "OCPP_2.1", "ISO_15118_2", "ISO_15118_20", "Other"],
            },
            v2xProtocol: {
              type: "string",
              enum: [
                "CHAdeMO_V2G",
                "CCS_BPT",
                "ISO_15118_20_AC_BPT",
                "ISO_15118_20_DC_BPT",
                "Other",
              ],
            },
          },
        },
      ],
    },
    EnergyResourceInverterAttributes: {
      description:
        "Attributes for grid-connected power-electronics inverters (type: INVERTER). IEEE 1547-2018 / SunSpec DER Models 702-714. CIM: PowerElectronicsConnection (IEC 61970-302).",
      allOf: [
        {
          $ref: "#/$defs/EnergyResourceCommonAttributes",
        },
        {
          type: "object",
          properties: {
            ratedApparentPower: {
              description:
                "Rated apparent power. unit: kVA | MVA. SunSpec Model 702 maxVA. CIM: PowerElectronicsConnection.ratedS.",
              $ref: "#/$defs/QVApparentPower",
            },
            maxReactivePower: {
              description:
                "Max reactive power injection (leading / over-excited). unit: kVAR | MVAR. Always ≥0. SunSpec Model 702 maxVar. CIM: PowerElectronicsConnection.maxQ.",
              $ref: "#/$defs/QVReactivePower",
            },
            minReactivePower: {
              description:
                "Max reactive power absorption (lagging / under-excited). unit: kVAR | MVAR. Value typically negative. SunSpec Model 702 maxVarNeg. CIM: PowerElectronicsConnection.minQ.",
              $ref: "#/$defs/QVReactivePower",
            },
            rideThroughCategory: {
              type: "string",
              enum: ["CategoryI", "CategoryII", "CategoryIII"],
              description: "IEEE 1547-2018 abnormal operating performance category.",
            },
            operatingMode: {
              type: "string",
              enum: ["GridFollowing", "GridForming", "Standby"],
            },
            voltVarEnabled: {
              type: "boolean",
            },
            freqDroopEnabled: {
              type: "boolean",
            },
            enterServiceRampTimeSec: {
              type: "number",
              minimum: 0,
            },
          },
        },
      ],
    },
    EnergyResourceLoadAttributes: {
      description:
        "Attributes for controllable electrical loads. CIM: EnergyConsumer / ConformLoad (IEC 61970-301).",
      allOf: [
        {
          $ref: "#/$defs/EnergyResourceCommonAttributes",
        },
        {
          type: "object",
          properties: {
            controlProtocol: {
              type: "string",
              enum: ["OpenADR_2.0b", "OCPP_2.0.1", "SunSpec_Modbus", "EEBus", "Modbus", "Other"],
            },
            loadCategory: {
              type: "string",
              enum: ["Heating", "Cooling", "WaterHeating", "Lighting", "EV", "Industrial", "Other"],
            },
          },
        },
      ],
    },
    EnergyResourceNetworkAttributes: {
      description:
        "Attributes for distribution network topology elements. CIM: PowerTransformer (DT), BusbarSection (BUS), Feeder (FEEDER), Substation/custom (MICROGRID).",
      allOf: [
        {
          $ref: "#/$defs/EnergyResourceCommonAttributes",
        },
        {
          type: "object",
          properties: {
            nominalVoltage: {
              description:
                "Nominal operating voltage. unit: V | kV. CIM: BaseVoltage.nominalVoltage.",
              $ref: "#/$defs/QVVoltage",
            },
            zone: {
              type: "string",
            },
            substationId: {
              type: "string",
            },
            feederCode: {
              type: "string",
            },
          },
        },
      ],
    },
    EnergyResourceMeter: {
      type: "object",
      description: "Metering device. CIM: Meter extends EndDevice (IEC 61968-9).",
      properties: {
        type: {
          type: "string",
          const: "METER",
        },
        attributes: {
          $ref: "#/$defs/EnergyResourceMeterAttributes",
        },
      },
    },
    EnergyResourceGenerator: {
      type: "object",
      description:
        "Electrical generation asset. SOLAR is deprecated — use SOLAR_PV. CIM: GeneratingUnit subtypes (IEC 61970-302).",
      properties: {
        type: {
          type: "string",
          enum: ["SOLAR_PV", "SOLAR", "WIND", "HYDRO", "BIOGAS", "CHP", "FUEL_CELL"],
        },
        attributes: {
          $ref: "#/$defs/EnergyResourceGeneratorAttributes",
        },
      },
    },
    EnergyResourceStorage: {
      type: "object",
      description:
        "Stationary energy storage asset. BATTERY is deprecated — use BESS. CIM: BatteryUnit (IEC 61970-302).",
      properties: {
        type: {
          type: "string",
          enum: ["BESS", "BATTERY"],
        },
        attributes: {
          $ref: "#/$defs/EnergyResourceStorageAttributes",
        },
      },
    },
    EnergyResourceEVCharger: {
      type: "object",
      description:
        "EV charging station (EVSE). A flexible load — NOT a storage resource. CIM: ElectricVehicleChargingStation (CIM17+).",
      properties: {
        type: {
          type: "string",
          enum: ["EV_CHARGER", "EV_V2G"],
        },
        attributes: {
          $ref: "#/$defs/EnergyResourceEVChargerAttributes",
        },
      },
    },
    EnergyResourceInverter: {
      type: "object",
      description:
        "Grid-connected power-electronics inverter. CIM: PowerElectronicsConnection (IEC 61970-302).",
      properties: {
        type: {
          type: "string",
          const: "INVERTER",
        },
        attributes: {
          $ref: "#/$defs/EnergyResourceInverterAttributes",
        },
      },
    },
    EnergyResourceLoad: {
      type: "object",
      description:
        "Controllable electrical load. CIM: EnergyConsumer / ConformLoad (IEC 61970-301).",
      properties: {
        type: {
          type: "string",
          enum: ["SMART_HVAC", "SMART_WATER_HEATER", "CONTROLLABLE_LOAD"],
        },
        attributes: {
          $ref: "#/$defs/EnergyResourceLoadAttributes",
        },
      },
    },
    EnergyResourceNetwork: {
      type: "object",
      description:
        "Distribution network topology element. CIM: DT=PowerTransformer, BUS=BusbarSection, FEEDER=Feeder, MICROGRID=Substation/custom (IEC 61970-301).",
      properties: {
        type: {
          type: "string",
          enum: ["DT", "BUS", "FEEDER", "MICROGRID"],
        },
        attributes: {
          $ref: "#/$defs/EnergyResourceNetworkAttributes",
        },
      },
    },
    EnergyResource: {
      type: "object",
      description:
        "Composable energy resource, discriminated by 'type' into one of seven kinds. id and type are required.",
      required: ["id", "type"],
      properties: {
        id: {
          type: "string",
          minLength: 1,
        },
        subResources: {
          type: "array",
          items: {
            oneOf: [
              {
                type: "string",
              },
              {
                $ref: "#/$defs/EnergyResource",
              },
            ],
          },
        },
        parentResources: {
          type: "array",
          items: {
            type: "string",
          },
        },
      },
      oneOf: [
        {
          $ref: "#/$defs/EnergyResourceMeter",
        },
        {
          $ref: "#/$defs/EnergyResourceGenerator",
        },
        {
          $ref: "#/$defs/EnergyResourceStorage",
        },
        {
          $ref: "#/$defs/EnergyResourceEVCharger",
        },
        {
          $ref: "#/$defs/EnergyResourceInverter",
        },
        {
          $ref: "#/$defs/EnergyResourceLoad",
        },
        {
          $ref: "#/$defs/EnergyResourceNetwork",
        },
      ],
    },
    Location: {
      type: "object",
      required: ["geo"],
      properties: {
        geo: {
          $ref: "#/$defs/GeoJSONGeometry",
        },
        address: {
          $ref: "#/$defs/Address",
        },
      },
    },
    GeoJSONGeometry: {
      type: "object",
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
        },
        geometries: {
          type: "array",
          items: {
            $ref: "#/$defs/GeoJSONGeometry",
          },
        },
        bbox: {
          type: "array",
          minItems: 4,
          maxItems: 4,
          items: {
            type: "number",
          },
        },
      },
      additionalProperties: true,
    },
    Address: {
      type: "object",
      additionalProperties: false,
      properties: {
        streetAddress: {
          type: "string",
        },
        extendedAddress: {
          type: "string",
        },
        addressLocality: {
          type: "string",
        },
        addressRegion: {
          type: "string",
        },
        postalCode: {
          type: "string",
        },
        addressCountry: {
          type: "string",
        },
      },
    },
  },
};

const iesElectricityCredentialV1_2Checksum = canonicalJsonSha256(
  iesElectricityCredentialV1_2Schema,
);

export const iesElectricityCredentialV1_2Definition: SchemaDefinition = {
  id: "ies/electricity-credential/v1.2",
  schema: iesElectricityCredentialV1_2Schema,
  // Hosted JSON-LD context — required for canonicalizing proof formats
  // (data-integrity / jws-2020). A pinned, @import-inlined snapshot is
  // bundled in @opencred/vc-core under this URL.
  contextUrl:
    "https://india-energy-stack.github.io/ies-accelerator/schemas/ElectricityCredential/v1.2/context.jsonld",
  version: "1.2.0",
  lastUpdated: "2026-06-12T00:00:00Z",
  checksum: iesElectricityCredentialV1_2Checksum,
  source: {
    kind: "referenced",
    upstreamUrl: "https://schema.beckn.io/ElectricityCredential/1.2/schema.json",
    upstreamOwner: "India Energy Stack",
    upstreamLicense: "MIT",
  },
  category: "utility",
};

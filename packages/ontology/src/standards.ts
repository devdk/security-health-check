/**
 * External standards the ontology maps onto. Labels are the official MITRE names, so a
 * finding can be cross-referenced with any tool that speaks CWE or CAPEC.
 */

/** MITRE CWE: what is wrong (the weakness). */
export const WEAKNESSES = {
  'cwe/200': 'Exposure of Sensitive Information to an Unauthorized Actor',
  'cwe/203': 'Observable Discrepancy',
  'cwe/269': 'Improper Privilege Management',
  'cwe/307': 'Improper Restriction of Excessive Authentication Attempts',
  'cwe/308': 'Use of Single-factor Authentication',
  'cwe/319': 'Cleartext Transmission of Sensitive Information',
  'cwe/326': 'Inadequate Encryption Strength',
  'cwe/327': 'Use of a Broken or Risky Cryptographic Algorithm',
  'cwe/434': 'Unrestricted Upload of File with Dangerous Type',
  'cwe/489': 'Active Debug Code',
  'cwe/497': 'Exposure of Sensitive System Information to an Unauthorized Control Sphere',
  'cwe/506': 'Embedded Malicious Code',
  'cwe/527': 'Exposure of Version-Control Repository to an Unauthorized Control Sphere',
  'cwe/530': 'Exposure of Backup File to an Unauthorized Control Sphere',
  'cwe/532': 'Insertion of Sensitive Information into Log File',
  'cwe/538': 'Insertion of Sensitive Information into Externally-Accessible File or Directory',
  'cwe/548': 'Exposure of Information Through Directory Listing',
  'cwe/614': "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
  'cwe/693': 'Protection Mechanism Failure',
  'cwe/732': 'Incorrect Permission Assignment for Critical Resource',
  'cwe/1004': "Sensitive Cookie Without 'HttpOnly' Flag",
  'cwe/1021': 'Improper Restriction of Rendered UI Layers or Frames',
  'cwe/1104': 'Use of Unmaintained Third Party Components',
  'cwe/1275': 'Sensitive Cookie with Improper SameSite Attribute',
  'cwe/1395': 'Dependency on Vulnerable Third-Party Component',
} as const;
export type WeaknessId = keyof typeof WEAKNESSES;

/** MITRE CAPEC: how an attacker would use it (the attack pattern). */
export const ATTACK_PATTERNS = {
  'capec/16': 'Dictionary-based Password Attack',
  'capec/31': 'Accessing/Intercepting/Modifying HTTP Cookies',
  'capec/49': 'Password Brute Forcing',
  'capec/63': 'Cross-Site Scripting (XSS)',
  'capec/87': 'Forceful Browsing',
  'capec/94': 'Adversary in the Middle (AiTM)',
  'capec/103': 'Clickjacking',
  'capec/127': 'Directory Indexing',
  'capec/157': 'Sniffing Attacks',
  'capec/170': 'Web Application Fingerprinting',
  'capec/575': 'Account Footprinting',
  'capec/620': 'Drop Encryption Level',
} as const;
export type AttackPatternId = keyof typeof ATTACK_PATTERNS;

/** OWASP Top 10 (2021) categories. */
export const OWASP_TOP10_2021 = {
  'A01:2021': 'Broken Access Control',
  'A02:2021': 'Cryptographic Failures',
  'A05:2021': 'Security Misconfiguration',
  'A06:2021': 'Vulnerable and Outdated Components',
  'A07:2021': 'Identification and Authentication Failures',
  'A08:2021': 'Software and Data Integrity Failures',
} as const;
export type OwaspCategory = keyof typeof OWASP_TOP10_2021;

export function cweUrl(id: WeaknessId): string {
  return `https://cwe.mitre.org/data/definitions/${id.split('/')[1]}.html`;
}

export function capecUrl(id: AttackPatternId): string {
  return `https://capec.mitre.org/data/definitions/${id.split('/')[1]}.html`;
}

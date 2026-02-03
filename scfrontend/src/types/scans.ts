export type Scan = {
  scan_id: number;
  ip: string;
  timing: number;
  created_at: string;

  portscan?: { scan_result?: string; scan_id?: number };
  bannergrab?: { scan_result?: string; scan_id?: number };
  vulnerabilityscan?: { vulnerabilities?: string; scan_id?: number };
  subdomainl1?: { [k: string]: any; scan_id?: number };
  smbshares?: { scan_result?: string; scan_id?: number };

  cves?: {
    scan_id?: number;
    cves?: Record<string, CveDetails>;
  };

  metamodules?: {
    scan_id?: number;
    results?: Record<string, MetamoduleResult[]>;
  };

  whatweb?: {
    report_for?: string | null;
    status?: string | null;
    title?: string | null;
    ip?: string | null;
    country?: string | null;
    summary_plugins?: { name: string; summary_values: string[] }[];
    detected_plugins?: Record<string, any>;
    http_headers?: Record<string, any>;
    scan_id?: number;
  };
};

export type CveDetails = {
  cveId: string;
  description_en?: string;
  affected?: {
    vendor?: string;
    product?: string;
    defaultStatus?: string | null;
    versions?: Array<{
      version?: string;
      status?: string;
      lessThan?: string;
      lessThanOrEqual?: string;
      versionType?: string;
    }>;
  }[];
  cvss?: {
    cvssV3_1?: CvssV3;
    cvssV3_0?: CvssV3;
    cvssV2_0?: CvssV2;
  };
};

export type CvssV3 = {
  version: string;
  baseScore: number;
  baseSeverity?: string;
  vectorString?: string;
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  scope?: string;
  confidentialityImpact?: string;
  integrityImpact?: string;
  availabilityImpact?: string;
};

export type CvssV2 = {
  version: string;
  baseScore: number;
  baseSeverity?: string;
  vectorString?: string;
};

export type MetamoduleResult = {
  module_name: string;
  module_type: string;
  module_refname: string;
  rank?: string;
  disclosure_date?: string | null;
  search_fullname?: string | null;
  search_refname?: string | null;
  search_path?: string | null;
  description?: string;
  loaded_fullname?: string;
};

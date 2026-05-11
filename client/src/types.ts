export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingType =
  | 'comment'
  | 'form'
  | 'link'
  | 'package'
  | 'secret'
  | 'script:external'
  | 'script:internal'
  | 'script:in-element';

export interface Vulnerability {
  severity: SeverityLevel;
  description: string;
  recommendation: string;
}

export interface CodeFinding {
  type: FindingType;
  content: string;
  lines: number | number[];
  vulnerabilities: Vulnerability[];
}

export interface Link {
  type: 'absolute' | 'relative';
  link: string;
}

export interface HeaderFinding {
  header: string;
  present: boolean;
  value: string | null;
  severity: SeverityLevel;
  description: string;
  recommendation: string;
}

export interface Site {
  path: string;
  html_content: string;
  links: Link[];
  response_headers: Record<string, string>;
  code_analysis: CodeFinding[];
  header_analysis: HeaderFinding[];
}

export interface ScanData {
  certificate: string;
  sites: Site[];
  robots_txt: RobotsTxtResult | null;
}

export interface RobotsTxtRule {
  user_agent: string;
  disallowed: string[];
  allowed: string[];
}

export interface RobotsTxtResult {
  found: boolean;
  raw: string | null;
  rules: RobotsTxtRule[];
  sitemaps: string[];
  crawl_delay: number | null;
}

export interface PathCardStats {
  total: number;
  vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
}

export interface OverallStatsData {
  totalPages: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export type ViewMode = 'findings' | 'code';

export type FindingTabKey =
  | 'all'
  | 'vulnerabilities'
  | 'scripts'
  | 'forms'
  | 'secrets'
  | 'comments';

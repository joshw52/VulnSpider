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

export interface Site {
  path: string;
  html_content: string;
  links: Link[];
  response_headers: Record<string, string>;
  code_analysis: CodeFinding[];
}

export interface ScanData {
  certificate: string;
  sites: Site[];
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

import { useState } from 'react';
import {
  Badge,
  Button,
  Card,
  Code,
  Divider,
  Group,
  ScrollArea,
  Stack,
  Tabs,
  Text,
  TextInput,
  Title,
  Accordion,
  Paper,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { CodeHighlight } from '@mantine/code-highlight';
import {
  IconCheck,
  IconCode,
  IconFileText,
  IconSearch,
  IconShieldCheck,
  IconX,
} from '@tabler/icons-react';

import './App.css';
import type {
  ScanData,
  Site,
  CodeFinding,
  ViewMode,
  FindingTabKey,
  PathCardStats,
  OverallStatsData,
  SeverityLevel,
  FindingType,
} from './types';

const API_URL = import.meta.env.VITE_API_URL as string;

function App() {
  const [scanData, setScanData] = useState<ScanData | null>(null);
  const [selectedPath, setSelectedPath] = useState<string>('');
  const [viewMode, setViewMode] = useState<ViewMode>('findings');
  const [loading, setLoading] = useState(false);

  const handleScan = async (url: string) => {
    setLoading(true);
    const notifId = notifications.show({
      loading: true,
      title: 'Scanning…',
      message: 'Crawling and analysing the site, this may take a moment.',
      autoClose: false,
      withCloseButton: false,
    });
    try {
      const response = await fetch(`${API_URL}/crawl`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Scan failed');
      }
      const data: ScanData = await response.json();
      data.sites = data.sites.map((site) => ({
        ...site,
        code_analysis: Array.isArray(site.code_analysis) ? site.code_analysis : [],
      }));
      setScanData(data);
      if (data.sites.length > 0) {
        setSelectedPath(data.sites[0].path);
      }
      notifications.update({
        id: notifId,
        loading: false,
        title: 'Scan complete',
        message: `Found ${data.sites.length} page${data.sites.length !== 1 ? 's' : ''}.`,
        color: 'teal',
        icon: <IconCheck size={16} />,
        autoClose: 4000,
        withCloseButton: true,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'An unknown error occurred';
      notifications.update({
        id: notifId,
        loading: false,
        title: 'Scan failed',
        message: msg,
        color: 'red',
        icon: <IconX size={16} />,
        autoClose: 6000,
        withCloseButton: true,
      });
    } finally {
      setLoading(false);
    }
  };

  if (!scanData) {
    return (
      <div className="app">
        <header className="app-header">
          <Group gap="xs" h="100%" px="md">
            <IconShieldCheck size={24} />
            <Title order={3}>Web Vulnerability Scanner</Title>
          </Group>
        </header>
        <main className="app-main app-main--centered">
          <ScanForm loading={loading} onScan={handleScan} />
        </main>
      </div>
    );
  }

  const selectedSite = scanData.sites.find((site) => site.path === selectedPath);

  if (!selectedSite) {
    return (
      <div className="app">
        <header className="app-header">
          <Group h="100%" px="md" gap="xs">
            <IconShieldCheck size={24} />
            <Title order={3}>Web Vulnerability Scanner</Title>
          </Group>
        </header>
        <main className="app-main app-main--centered">
          <Text c="dimmed" ta="center">
            No pages found for this scan.
          </Text>
        </main>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="app-header">
        <Group gap="xs" h="100%" px="md">
          <IconShieldCheck size={24} />
          <Title order={3}>Web Vulnerability Scanner</Title>
        </Group>
      </header>

      <div className="app-body">
        <nav className="app-navbar">
          <div className="navbar-title">
            <Text fw={600} size="sm">
              Scanned Pages
            </Text>
          </div>

          <ScrollArea className="navbar-scroll">
            <Stack gap="xs" p="sm">
              {scanData.sites.map((site) => (
                <PathCard
                  isSelected={selectedPath === site.path}
                  key={site.path}
                  site={site}
                  onClick={() => setSelectedPath(site.path)}
                />
              ))}
            </Stack>
          </ScrollArea>

          <div className="navbar-footer">
            <Divider />
            <div className="navbar-footer-section">
              <Text fw={600} size="sm" mb="xs">
                Overall Statistics
              </Text>
              <OverallStats scanData={scanData} />
            </div>
            <Divider />
            <div className="navbar-footer-section">
              <Button
                fullWidth
                leftSection={<IconSearch size={16} />}
                onClick={() => setScanData(null)}
                variant="light"
              >
                New Scan
              </Button>
            </div>
          </div>
        </nav>

        <main className="app-main">
          <Group className="content-header" justify="space-between" mb="md">
            <Title order={4}>{selectedPath}</Title>
            <Group gap="xs">
              <Button
                leftSection={<IconFileText size={16} />}
                onClick={() => setViewMode('findings')}
                size="sm"
                variant={viewMode === 'findings' ? 'filled' : 'light'}
              >
                Findings
              </Button>
              <Button
                leftSection={<IconCode size={16} />}
                onClick={() => setViewMode('code')}
                size="sm"
                variant={viewMode === 'code' ? 'filled' : 'light'}
              >
                Code View
              </Button>
            </Group>
          </Group>

          {viewMode === 'findings' ? (
            <FindingsView site={selectedSite} />
          ) : (
            <CodeView site={selectedSite} />
          )}
        </main>
      </div>
    </div>
  );
}

interface ScanFormProps {
  onScan: (url: string) => void;
  loading: boolean;
}

function ScanForm({ onScan, loading }: ScanFormProps) {
  const [url, setUrl] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) onScan(url.trim());
  };

  return (
    <div className="scan-form-wrapper">
      <Paper className="scan-form-card" p="xl" radius="md">
        <Stack gap="md">
          <div>
            <Title order={3} mb={4}>
              Scan a Website
            </Title>
            <Text c="dimmed" size="sm">
              Enter a URL to crawl and analyse for security vulnerabilities.
            </Text>
          </div>
          <form onSubmit={handleSubmit}>
            <Group align="flex-end" gap="sm">
              <TextInput
                disabled={loading}
                flex={1}
                leftSection={<IconSearch size={16} />}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                required
                type="url"
                value={url}
              />
              <Button
                disabled={loading || !url.trim()}
                leftSection={<IconSearch size={16} />}
                type="submit"
              >
                {loading ? 'Scanning...' : 'Scan'}
              </Button>
            </Group>
          </form>
        </Stack>
      </Paper>
    </div>
  );
}

interface PathCardProps {
  site: Site;
  isSelected: boolean;
  onClick: () => void;
}

function PathCard({ site, isSelected, onClick }: PathCardProps) {
  const stats: PathCardStats = {
    total: site.code_analysis.length,
    vulnerabilities: site.code_analysis.filter((f) => f.vulnerabilities.length > 0).length,
    critical: site.code_analysis.filter((f) =>
      f.vulnerabilities.some((v) => v.severity === 'critical'),
    ).length,
    high: site.code_analysis.filter((f) => f.vulnerabilities.some((v) => v.severity === 'high'))
      .length,
    medium: site.code_analysis.filter((f) => f.vulnerabilities.some((v) => v.severity === 'medium'))
      .length,
  };

  const maxSeverity =
    stats.critical > 0
      ? 'critical'
      : stats.high > 0
        ? 'high'
        : stats.medium > 0
          ? 'medium'
          : 'safe';

  const severityColor: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'yellow',
    safe: 'teal',
  };

  return (
    <Card
      className={`path-card ${isSelected ? 'selected' : ''} severity-border-${maxSeverity}`}
      onClick={onClick}
      padding="sm"
      radius="md"
      style={{ cursor: 'pointer' }}
    >
      <Group gap="xs" mb={4}>
        <IconFileText size={14} />
        <Text fw={600} size="sm" style={{ wordBreak: 'break-all' }}>
          {site.path}
        </Text>
      </Group>
      <Text c="dimmed" size="xs">
        {stats.total} findings
      </Text>
      {stats.vulnerabilities > 0 && (
        <Text c="red.4" size="xs">
          ⚠️ {stats.vulnerabilities} vulnerabilities
        </Text>
      )}
      {maxSeverity !== 'safe' && (
        <Badge color={severityColor[maxSeverity]} mt={4} size="xs" variant="light">
          {maxSeverity.toUpperCase()}
        </Badge>
      )}
    </Card>
  );
}

interface OverallStatsProps {
  scanData: ScanData;
}

function OverallStats({ scanData }: OverallStatsProps) {
  const allFindings = scanData.sites.flatMap((s) => s.code_analysis);
  const stats: OverallStatsData = {
    totalPages: scanData.sites.length,
    totalFindings: allFindings.length,
    critical: allFindings.filter((f) => f.vulnerabilities.some((v) => v.severity === 'critical'))
      .length,
    high: allFindings.filter((f) => f.vulnerabilities.some((v) => v.severity === 'high')).length,
    medium: allFindings.filter((f) => f.vulnerabilities.some((v) => v.severity === 'medium'))
      .length,
    low: allFindings.filter((f) => f.vulnerabilities.some((v) => v.severity === 'low')).length,
  };

  return (
    <Stack gap={4}>
      <Group justify="space-between">
        <Text c="dimmed" size="xs">
          Pages
        </Text>
        <Text fw={600} size="xs">
          {stats.totalPages}
        </Text>
      </Group>
      <Group justify="space-between">
        <Text c="dimmed" size="xs">
          Findings
        </Text>
        <Text fw={600} size="xs">
          {stats.totalFindings}
        </Text>
      </Group>
      {stats.critical > 0 && (
        <Group justify="space-between">
          <Text c="red.4" size="xs">
            Critical
          </Text>
          <Text c="red.4" fw={700} size="xs">
            {stats.critical}
          </Text>
        </Group>
      )}
      {stats.high > 0 && (
        <Group justify="space-between">
          <Text c="orange.4" size="xs">
            High
          </Text>
          <Text c="orange.4" fw={700} size="xs">
            {stats.high}
          </Text>
        </Group>
      )}
      {stats.medium > 0 && (
        <Group justify="space-between">
          <Text c="yellow.4" size="xs">
            Medium
          </Text>
          <Text c="yellow.4" fw={700} size="xs">
            {stats.medium}
          </Text>
        </Group>
      )}
      {stats.low > 0 && (
        <Group justify="space-between">
          <Text c="teal.4" size="xs">
            Low
          </Text>
          <Text c="teal.4" fw={700} size="xs">
            {stats.low}
          </Text>
        </Group>
      )}
    </Stack>
  );
}

interface FindingsViewProps {
  site: Site;
}

function FindingsView({ site }: FindingsViewProps) {
  const groupedFindings: Record<FindingTabKey, CodeFinding[]> = {
    all: site.code_analysis,
    vulnerabilities: site.code_analysis.filter((f) => f.vulnerabilities.length > 0),
    scripts: site.code_analysis.filter((f) => f.type.startsWith('script')),
    forms: site.code_analysis.filter((f) => f.type === 'form'),
    secrets: site.code_analysis.filter((f) => f.type === 'secret'),
    comments: site.code_analysis.filter((f) => f.type === 'comment'),
  };

  return (
    <Tabs className="findings-tabs" defaultValue="all">
      <Tabs.List mb="md">
        {(Object.entries(groupedFindings) as [FindingTabKey, CodeFinding[]][]).map(
          ([key, findings]) => (
            <Tabs.Tab key={key} value={key}>
              {key.charAt(0).toUpperCase() + key.slice(1)} ({findings.length})
            </Tabs.Tab>
          ),
        )}
      </Tabs.List>

      {(Object.entries(groupedFindings) as [FindingTabKey, CodeFinding[]][]).map(
        ([key, findings]) => (
          <Tabs.Panel key={key} value={key}>
            {findings.length === 0 ? (
              <Text c="dimmed" ta="center" mt="xl">
                ✅ No {key} found
              </Text>
            ) : (
              <Accordion classNames={{ item: 'finding-accordion-item' }} variant="separated">
                {findings.map((finding, idx) => (
                  <FindingCard finding={finding} idx={idx} key={idx} />
                ))}
              </Accordion>
            )}
          </Tabs.Panel>
        ),
      )}
    </Tabs>
  );
}

interface FindingCardProps {
  finding: CodeFinding;
  idx: number;
}

function FindingCard({ finding, idx }: FindingCardProps) {
  const hasVulnerabilities = finding.vulnerabilities.length > 0;

  return (
    <Accordion.Item value={String(idx)} className={hasVulnerabilities ? 'has-vuln' : ''}>
      <Accordion.Control>
        <Group gap="sm">
          <Text size="sm">{getTypeIcon(finding.type)}</Text>
          <Text size="sm" fw={600}>
            {finding.type}
          </Text>
          <Text size="xs" c="dimmed">
            Line{Array.isArray(finding.lines) ? 's' : ''}:{' '}
            {Array.isArray(finding.lines) ? finding.lines.join(', ') : finding.lines}
          </Text>
          {hasVulnerabilities && (
            <Badge color="red" size="xs" variant="light">
              ⚠️ {finding.vulnerabilities.length} vuln
              {finding.vulnerabilities.length !== 1 ? 's' : ''}
            </Badge>
          )}
        </Group>
      </Accordion.Control>
      <Accordion.Panel>
        <Stack gap="sm">
          <div>
            <Text c="dimmed" fw={600} mb={4} size="xs" tt="uppercase">
              Code
            </Text>
            <Code block>{finding.content}</Code>
          </div>
          {finding.vulnerabilities.length > 0 && (
            <div>
              <Text size="sm" fw={600} mb="xs">
                Vulnerabilities
              </Text>
              <Stack gap="xs">
                {finding.vulnerabilities.map((vuln, i) => (
                  <Paper
                    className={`vuln-paper vuln-${vuln.severity ?? 'info'}`}
                    key={i}
                    p="sm"
                    radius="sm"
                  >
                    <Group gap="xs" mb={4}>
                      <SeverityBadge severity={vuln.severity} />
                    </Group>
                    <Text size="sm">
                      <strong>Description:</strong> {vuln.description}
                    </Text>
                    <Text size="sm">
                      <strong>Recommendation:</strong> {vuln.recommendation}
                    </Text>
                  </Paper>
                ))}
              </Stack>
            </div>
          )}
        </Stack>
      </Accordion.Panel>
    </Accordion.Item>
  );
}

interface CodeViewProps {
  site: Site;
}

function CodeView({ site }: CodeViewProps) {
  const htmlContent = atob(site.html_content);
  const [selectedFinding, setSelectedFinding] = useState<CodeFinding | null>(null);

  const lineToFindings: Record<number, CodeFinding[]> = {};
  site.code_analysis.forEach((finding) => {
    const lineNumbers = Array.isArray(finding.lines) ? finding.lines : [finding.lines];
    lineNumbers.forEach((line) => {
      if (!lineToFindings[line]) lineToFindings[line] = [];
      lineToFindings[line].push(finding);
    });
  });

  const lines = htmlContent.split('\n');

  return (
    <div className="code-view-container">
      <div className="code-panel">
        <Group className="code-panel-header" justify="space-between" px="md" py="sm">
          <Text fw={600} size="sm">
            Source Code
          </Text>
          <Text c="dimmed" size="xs">
            {lines.length} lines
          </Text>
        </Group>
        <ScrollArea className="code-scroll">
          <pre className="code-display">
            {lines.map((line, idx) => {
              const lineNum = idx + 1;
              const findings = lineToFindings[lineNum];
              const hasVuln = findings?.some((f) => f.vulnerabilities.length > 0);
              return (
                <div
                  key={idx}
                  className={`code-line ${findings ? 'has-finding' : ''} ${hasVuln ? 'has-vuln' : ''}`}
                  onClick={() => findings && setSelectedFinding(findings[0])}
                >
                  <span className="line-number">{lineNum}</span>
                  <span className="line-content">{line}</span>
                </div>
              );
            })}
          </pre>
        </ScrollArea>
      </div>

      <div className="details-panel">
        <Text fw={600} mb="sm" size="sm">
          Finding Details
        </Text>
        <Divider mb="sm" />
        {selectedFinding ? (
          <Stack gap="sm">
            <div>
              <Text c="dimmed" fw={600} mb={4} size="xs" tt="uppercase">
                Code
              </Text>
              <CodeHighlight code={selectedFinding.content} language="html" />
            </div>
            {selectedFinding.vulnerabilities.length > 0 && (
              <div>
                <Text size="sm" fw={600} mb="xs">
                  Vulnerabilities
                </Text>
                <Stack gap="xs">
                  {selectedFinding.vulnerabilities.map((vuln, i) => (
                    <Paper
                      className={`vuln-paper vuln-${vuln.severity ?? 'info'}`}
                      key={i}
                      p="sm"
                      radius="sm"
                    >
                      <Group gap="xs" mb={4}>
                        <SeverityBadge severity={vuln.severity} />
                      </Group>
                      <Text size="sm">
                        <strong>Description:</strong> {vuln.description}
                      </Text>
                      <Text size="sm">
                        <strong>Recommendation:</strong> {vuln.recommendation}
                      </Text>
                    </Paper>
                  ))}
                </Stack>
              </div>
            )}
          </Stack>
        ) : (
          <Text c="dimmed" size="sm" ta="center">
            Click on a highlighted line to see details
          </Text>
        )}
      </div>
    </div>
  );
}

interface SeverityBadgeProps {
  severity: SeverityLevel;
}

function SeverityBadge({ severity }: SeverityBadgeProps) {
  const colorMap: Record<SeverityLevel, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'yellow',
    low: 'teal',
    info: 'gray',
  };
  const color = colorMap[severity] ?? 'gray';
  return (
    <Badge color={color} size="sm" variant="filled">
      {(severity ?? 'info').toUpperCase()}
    </Badge>
  );
}

function getTypeIcon(type: FindingType): string {
  const icons: Record<FindingType, string> = {
    'script:external': '🔗',
    'script:internal': '📜',
    'script:in-element': '⚡',
    form: '📝',
    comment: '💬',
    secret: '🔐',
    package: '📦',
    link: '🌐',
  };
  return icons[type] || '📄';
}

export default App;

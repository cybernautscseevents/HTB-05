import React, { useState } from 'react';
import type { Finding, ProbePlanReport, RemediationCandidate, RemediationReport, VulnerabilityScanResult } from './types/api';
import { acsaApi } from './api/client';
import { Header, type NavTab } from './components/Header';
import { RepositoryBar } from './components/RepositoryBar';
import { LoadingState } from './components/LoadingState';
import { ErrorState } from './components/ErrorState';
import { OverviewView } from './views/OverviewView';
import { FindingsView } from './views/FindingsView';
import { FindingDetailView } from './views/FindingDetailView';
import { RemediationView } from './views/RemediationView';
import { EvidenceView } from './views/EvidenceView';
import { ProbesView } from './views/ProbesView';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [repositoryPath, setRepositoryPath] = useState<string>('tests/fixtures/nodegoat');

  const [scanResult, setScanResult] = useState<VulnerabilityScanResult | null>(null);
  const [remediationReport, setRemediationReport] = useState<RemediationReport | null>(null);
  const [probePlan, setProbePlan] = useState<ProbePlanReport | null>(null);

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedFindingIdForProbe, setSelectedFindingIdForProbe] = useState<string | null>(null);

  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isRemediating, setIsRemediating] = useState<boolean>(false);
  const [isProbing, setIsProbing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (path: string) => {
    setIsScanning(true);
    setError(null);
    setSelectedFinding(null);
    setRepositoryPath(path);

    try {
      // 1. Scan repository
      const scanRes = await acsaApi.scanRepository(path);
      setScanResult(scanRes);

      // 2. Fetch remediation analysis non-blockingly
      acsaApi.remediateRepository(path)
        .then((remRes) => setRemediationReport(remRes))
        .catch(() => {
          // Remediation may be requested on-demand
        });

      // 3. Fetch probe plan if any unknown findings exist
      if (scanRes.unknown_count > 0) {
        acsaApi.planProbes(path)
          .then((probeRes) => setProbePlan(probeRes))
          .catch(() => {
            // Probes can be planned on-demand
          });
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setIsScanning(false);
    }
  };

  const handleGenerateRemediation = async () => {
    if (!repositoryPath) return;
    setIsRemediating(true);
    try {
      const res = await acsaApi.remediateRepository(repositoryPath);
      setRemediationReport(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Remediation analysis failed');
    } finally {
      setIsRemediating(false);
    }
  };

  const handlePlanProbes = async () => {
    if (!repositoryPath) return;
    setIsProbing(true);
    try {
      const res = await acsaApi.planProbes(repositoryPath);
      setProbePlan(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Dynamic probe planning failed');
    } finally {
      setIsProbing(false);
    }
  };

  const handleSelectFinding = (finding: Finding) => {
    setSelectedFinding(finding);
  };

  const handleBackFromDetail = () => {
    setSelectedFinding(null);
  };

  const handleViewRemediation = (_candidate?: RemediationCandidate | null) => {
    setSelectedFinding(null);
    setActiveTab('remediation');
    if (!remediationReport && !isRemediating) {
      handleGenerateRemediation();
    }
  };

  const handleViewProbes = (findingId: string) => {
    setSelectedFinding(null);
    setSelectedFindingIdForProbe(findingId);
    setActiveTab('probes');
    if (!probePlan && !isProbing) {
      handlePlanProbes();
    }
  };

  return (
    <div className="app-container">
      <Header
        activeTab={activeTab}
        onSelectTab={(tab) => {
          setSelectedFinding(null);
          setSelectedFindingIdForProbe(null);
          setActiveTab(tab);
        }}
        findingsCount={scanResult ? scanResult.findings.length : undefined}
        probesCount={probePlan ? probePlan.total_probes_generated : undefined}
      />

      <RepositoryBar
        currentPath={repositoryPath}
        isScanning={isScanning}
        onScan={handleScan}
      />

      <main className="main-content">
        {error && (
          <ErrorState
            message={error}
            onRetry={() => handleScan(repositoryPath)}
          />
        )}

        {isScanning && !error && (
          <LoadingState
            message="Analyzing repository supply chain..."
            subtext="Performing exact-version inventory resolution, OSV intelligence queries, AST reachability analysis, and evidence fusion."
          />
        )}

        {!isScanning && !error && (
          <>
            {selectedFinding ? (
              <FindingDetailView
                finding={selectedFinding}
                remediationCandidate={
                  remediationReport?.candidates?.find(
                    (c) => c.package_name === selectedFinding.component?.name || c.target_component === selectedFinding.component?.name
                  ) ||
                  remediationReport?.results
                    ?.find((r) => r.finding_id === selectedFinding.id || r.package_name === selectedFinding.component?.name)
                    ?.selected_candidate ||
                  remediationReport?.results
                    ?.find((r) => r.package_name === selectedFinding.component?.name)
                    ?.candidates?.[0] ||
                  null
                }
                onBack={handleBackFromDetail}
                onViewRemediation={handleViewRemediation}
                onViewProbes={handleViewProbes}
              />
            ) : (
              <>
                {activeTab === 'overview' && (
                  <OverviewView
                    scanResult={scanResult}
                    onSelectFinding={handleSelectFinding}
                    onViewAllFindings={() => setActiveTab('findings')}
                    onScan={() => handleScan(repositoryPath)}
                    onNavigateToRemediation={() => setActiveTab('remediation')}
                  />
                )}

                {activeTab === 'findings' && (
                  <FindingsView
                    findings={scanResult ? scanResult.findings : []}
                    onSelectFinding={handleSelectFinding}
                    onScan={() => handleScan(repositoryPath)}
                  />
                )}

                {activeTab === 'remediation' && (
                  <RemediationView
                    repositoryPath={repositoryPath}
                    remediationReport={remediationReport}
                    onGenerateRemediation={handleGenerateRemediation}
                    isLoading={isRemediating}
                  />
                )}

                {activeTab === 'evidence' && (
                  <EvidenceView
                    scanResult={scanResult}
                    onScan={() => handleScan(repositoryPath)}
                  />
                )}

                {activeTab === 'probes' && (
                  <ProbesView
                    probePlan={probePlan}
                    isLoading={isProbing}
                    onPlanProbes={handlePlanProbes}
                    selectedFindingId={selectedFindingIdForProbe}
                  />
                )}
              </>
            )}
          </>
        )}
      </main>
    </div>
  );
};

export default App;

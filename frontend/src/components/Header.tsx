import React, { useEffect, useState } from 'react';
import { acsaApi } from '../api/client';

export type NavTab = 'overview' | 'findings' | 'remediation' | 'evidence' | 'probes';

interface HeaderProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  findingsCount?: number;
  probesCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onSelectTab,
  findingsCount,
  probesCount,
}) => {
  const [apiConnected, setApiConnected] = useState<boolean | null>(null);

  useEffect(() => {
    let mounted = true;
    acsaApi.checkHealth()
      .then(() => {
        if (mounted) setApiConnected(true);
      })
      .catch(() => {
        if (mounted) setApiConnected(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <header className="app-header">
      <div className="header-top">
        <div className="brand-section">
          <span className="brand-title">ACSA</span>
          <span className="brand-subtitle">Artifact-Centric Security Analysis</span>
        </div>
        <div className="header-meta">
          <div
            className={`badge ${apiConnected === true ? 'badge-green' : apiConnected === false ? 'badge-amber' : 'badge-gray'}`}
            role="status"
            aria-label={`API Status: ${apiConnected === true ? 'Connected' : apiConnected === false ? 'Disconnected' : 'Checking'}`}
            title="FastAPI Backend Status"
          >
            <span className="badge-dot" aria-hidden="true" />
            <span>{apiConnected === true ? 'Backend Connected' : apiConnected === false ? 'Backend Offline' : 'Checking API'}</span>
          </div>
        </div>
      </div>
      <nav className="nav-bar" aria-label="Main Navigation">
        <button
          type="button"
          className={`nav-tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => onSelectTab('overview')}
        >
          Overview
        </button>
        <button
          type="button"
          className={`nav-tab ${activeTab === 'findings' ? 'active' : ''}`}
          onClick={() => onSelectTab('findings')}
        >
          Findings {typeof findingsCount === 'number' && findingsCount > 0 ? `(${findingsCount})` : ''}
        </button>
        <button
          type="button"
          className={`nav-tab ${activeTab === 'remediation' ? 'active' : ''}`}
          onClick={() => onSelectTab('remediation')}
        >
          Remediation
        </button>
        <button
          type="button"
          className={`nav-tab ${activeTab === 'evidence' ? 'active' : ''}`}
          onClick={() => onSelectTab('evidence')}
        >
          Evidence
        </button>
        <button
          type="button"
          className={`nav-tab ${activeTab === 'probes' ? 'active' : ''}`}
          onClick={() => onSelectTab('probes')}
        >
          Probes {typeof probesCount === 'number' && probesCount > 0 ? `(${probesCount})` : ''}
        </button>
      </nav>
    </header>
  );
};

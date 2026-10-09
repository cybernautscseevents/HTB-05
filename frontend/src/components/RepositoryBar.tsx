import React, { useState } from 'react';

interface RepositoryBarProps {
  currentPath: string;
  isScanning: boolean;
  onScan: (path: string) => void;
}

export const RepositoryBar: React.FC<RepositoryBarProps> = ({
  currentPath,
  isScanning,
  onScan,
}) => {
  const [inputPath, setInputPath] = useState(currentPath || 'tests/fixtures/nodegoat');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputPath.trim() && !isScanning) {
      onScan(inputPath.trim());
    }
  };

  const handleSelectPreset = (path: string) => {
    setInputPath(path);
    if (!isScanning) {
      onScan(path);
    }
  };

  return (
    <div className="repo-bar">
      <form onSubmit={handleSubmit} className="repo-input-group">
        <label htmlFor="repo-path-input" className="repo-input-label">
          Target Workspace:
        </label>
        <input
          id="repo-path-input"
          type="text"
          className="repo-input"
          placeholder="e.g. tests/fixtures/nodegoat or path/to/repo"
          value={inputPath}
          onChange={(e) => setInputPath(e.target.value)}
          disabled={isScanning}
        />
        <button
          type="submit"
          className="btn btn-primary"
          disabled={isScanning || !inputPath.trim()}
        >
          {isScanning ? 'Analyzing...' : 'Scan Repository'}
        </button>
      </form>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.775rem', color: 'var(--color-text-tertiary)' }}>Presets:</span>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => handleSelectPreset('tests/fixtures/nodegoat')}
          disabled={isScanning}
          title="OWASP NodeGoat real repository test fixture"
        >
          NodeGoat (Vulnerable)
        </button>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => handleSelectPreset('tests/fixtures/repo_basic')}
          disabled={isScanning}
          title="Clean repository test fixture"
        >
          Clean Repo
        </button>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => handleSelectPreset('tests/fixtures/repo_contradictory')}
          disabled={isScanning}
          title="Contradictory manifest/lockfile fixture"
        >
          Contradictory Fixture
        </button>
      </div>
    </div>
  );
};

import React from 'react';

interface LoadingStateProps {
  message?: string;
  subtext?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Analyzing repository artifacts...',
  subtext = 'Querying exact-version OSV intelligence, evaluating static reachability, and fusing evidence.',
}) => {
  return (
    <div className="state-container" role="status" aria-live="polite">
      <div className="spinner" aria-hidden="true" />
      <h3 className="state-title">{message}</h3>
      <p className="state-desc">{subtext}</p>
    </div>
  );
};

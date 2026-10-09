import React from 'react';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Unable to complete security analysis',
  message,
  onRetry,
}) => {
  return (
    <div className="state-container" role="alert">
      <div style={{ fontSize: '2rem' }} aria-hidden="true">⚠️</div>
      <h3 className="state-title">{title}</h3>
      <p className="state-desc" style={{ color: 'var(--status-red-text)' }}>{message}</p>
      {onRetry && (
        <button
          type="button"
          className="btn btn-secondary"
          onClick={onRetry}
        >
          Retry Analysis
        </button>
      )}
    </div>
  );
};

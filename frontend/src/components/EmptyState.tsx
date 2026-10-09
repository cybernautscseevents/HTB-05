import React from 'react';

interface EmptyStateProps {
  title?: string;
  description?: string;
  actionLabel?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = 'No repository analyzed yet',
  description = 'Run an analysis to generate evidence-backed supply chain findings from real repository artifacts.',
  actionLabel = 'Scan Repository',
  onAction,
}) => {
  return (
    <div className="state-container">
      <h3 className="state-title">{title}</h3>
      <p className="state-desc">{description}</p>
      {onAction && (
        <button
          type="button"
          className="btn btn-primary"
          onClick={onAction}
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
};

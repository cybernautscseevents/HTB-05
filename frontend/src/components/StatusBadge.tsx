import React from 'react';

interface StatusBadgeProps {
  status: string;
  variant?: 'green' | 'red' | 'amber' | 'gray';
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, variant, size = 'md' }) => {
  // Compute variant if not explicitly provided
  let computedVariant = variant || 'gray';

  if (!variant) {
    const s = status.toUpperCase();
    if (
      s === 'REACHABLE' ||
      s === 'CONFIRMED' ||
      s === 'FAILED' ||
      s === 'REMEDIATION_FAILED' ||
      s === 'AFFECTED'
    ) {
      computedVariant = 'red';
    } else if (
      s === 'PROVEN_REMEDIATED' ||
      s === 'PROVEN_NOT_AFFECTED' ||
      s === 'NOT_REACHABLE' ||
      s === 'NOT_AFFECTED' ||
      s === 'PASSED' ||
      s === 'CLOSED' ||
      s === 'PROVEN_CLOSED'
    ) {
      computedVariant = 'green';
    } else if (
      s === 'UNKNOWN' ||
      s === 'POTENTIALLY_AFFECTED' ||
      s === 'CONTRADICTORY' ||
      s === 'REQUIRES_VERIFICATION' ||
      s === 'REMEDIATION_PARTIALLY_VERIFIED' ||
      s === 'NOT_VERIFIED' ||
      s === 'EXPECTED_TO_CLOSE' ||
      s === 'PENDING'
    ) {
      computedVariant = 'amber';
    } else {
      computedVariant = 'gray';
    }
  }

  const badgeClass = `badge badge-${computedVariant} ${size === 'sm' ? 'btn-sm' : ''}`;

  return (
    <span className={badgeClass} role="status" aria-label={`Status: ${status}`}>
      <span className="badge-dot" aria-hidden="true" />
      <span>{status.replace(/_/g, ' ')}</span>
    </span>
  );
};

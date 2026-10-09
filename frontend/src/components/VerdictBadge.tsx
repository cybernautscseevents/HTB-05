import React from 'react';
import type { Verdict } from '../types/api';

interface VerdictBadgeProps {
  verdict: Verdict;
  size?: 'sm' | 'md';
}

export const VerdictBadge: React.FC<VerdictBadgeProps> = ({ verdict, size = 'md' }) => {
  let badgeClass = 'badge-gray';
  let icon = '⚪';
  let label: string = verdict;

  switch (verdict) {
    case 'PROVEN_EXPOSURE':
      badgeClass = 'badge-red';
      icon = '🔴';
      label = 'PROVEN EXPOSURE';
      break;
    case 'PROVEN_AFFECTED':
      badgeClass = 'badge-red';
      icon = '🔴';
      label = 'PROVEN AFFECTED';
      break;
    case 'POTENTIALLY_AFFECTED':
      badgeClass = 'badge-amber';
      icon = '🟡';
      label = 'POTENTIALLY AFFECTED';
      break;
    case 'UNKNOWN':
      badgeClass = 'badge-amber';
      icon = '🟡';
      label = 'UNKNOWN';
      break;
    case 'CONTRADICTORY':
      badgeClass = 'badge-amber';
      icon = '⚠️';
      label = 'CONTRADICTORY';
      break;
    case 'NOT_VERIFIED':
      badgeClass = 'badge-amber';
      icon = '⏳';
      label = 'NOT VERIFIED';
      break;
    case 'PROVEN_NOT_AFFECTED':
      badgeClass = 'badge-green';
      icon = '🟢';
      label = 'PROVEN NOT AFFECTED';
      break;
    default:
      badgeClass = 'badge-gray';
      icon = '⚪';
      label = verdict;
  }

  return (
    <span
      className={`badge ${badgeClass} ${size === 'sm' ? 'btn-sm' : ''}`}
      role="status"
      aria-label={`Verdict: ${label}`}
      title={`Verdict: ${label}`}
    >
      <span aria-hidden="true">{icon}</span>
      <span>{label}</span>
    </span>
  );
};

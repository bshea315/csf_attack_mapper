import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { analyticsApi, exportsApi } from '../api/client';
import { Download, X, Grid3X3, List, Info, ExternalLink, ChevronDown, ChevronRight, AlertCircle } from 'lucide-react';
import clsx from 'clsx';

// Color scale for heatmap - from gray (no coverage) to deep green (high coverage)
function getHeatmapColor(count: number, maxCount: number): string {
  if (count === 0) return 'bg-gray-200';

  const intensity = Math.min(count / Math.max(maxCount, 1), 1);

  if (intensity <= 0.2) return 'bg-red-300';
  if (intensity <= 0.4) return 'bg-orange-300';
  if (intensity <= 0.6) return 'bg-yellow-300';
  if (intensity <= 0.8) return 'bg-lime-400';
  return 'bg-green-500';
}

function getHeatmapTextColor(count: number, maxCount: number): string {
  if (count === 0) return 'text-gray-500';
  const intensity = Math.min(count / Math.max(maxCount, 1), 1);
  if (intensity > 0.6) return 'text-white';
  return 'text-gray-800';
}

// Tactic display order (following ATT&CK framework order)
const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

interface TechniqueDetail {
  technique_id: string;
  technique_name: string;
  detection_count: number;
  tactic: string;
  is_subtechnique?: boolean;
  parent_technique_id?: string | null;
  url?: string | null;
}

interface TechniqueModalData {
  technique_id: string;
  technique_name: string;
  description: string | null;
  tactics: string[];
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  url: string;
  detection_count: number;
  detections: Array<{
    id: number;
    detection_id: string;
    name: string;
    severity: string;
    status: string;
    confidence: number;
    method: string;
    rationale: string;
  }>;
  subtechniques: Array<{
    technique_id: string;
    technique_name: string;
    detection_count: number;
    url: string;
  }>;
}

export default function AttackCoverage() {
  const [viewMode, setViewMode] = useState<'heatmap' | 'list'>('heatmap');
  const [selectedTechnique, setSelectedTechnique] = useState<TechniqueDetail | null>(null);
  const [hoveredTechnique, setHoveredTechnique] = useState<TechniqueDetail | null>(null);
  const [expandedTechniques, setExpandedTechniques] = useState<Set<string>>(new Set());
  const [modalData, setModalData] = useState<TechniqueModalData | null>(null);
  const [isModalLoading, setIsModalLoading] = useState(false);
  const [showSubtechniques, setShowSubtechniques] = useState(true);

  const { data, isLoading } = useQuery({
    queryKey: ['attack-coverage'],
    queryFn: analyticsApi.getAttackCoverage,
  });

  const handleTechniqueClick = async (tech: TechniqueDetail) => {
    setSelectedTechnique({ ...tech });
    setIsModalLoading(true);
    try {
      const details = await analyticsApi.getTechniqueDetails(tech.technique_id);
      setModalData(details);
    } catch (error) {
      console.error('Failed to fetch technique details:', error);
    } finally {
      setIsModalLoading(false);
    }
  };

  const closeModal = () => {
    setModalData(null);
    setSelectedTechnique(null);
  };

  const toggleTechniqueExpand = (techniqueId: string) => {
    setExpandedTechniques(prev => {
      const next = new Set(prev);
      if (next.has(techniqueId)) {
        next.delete(techniqueId);
      } else {
        next.add(techniqueId);
      }
      return next;
    });
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  if (!data) return null;

  // Calculate max detection count for color scaling
  const allTechniques = Object.values(data.techniques_by_tactic).flat();
  const maxDetectionCount = Math.max(...allTechniques.map(t => t.detection_count), 1);

  // Sort tactics by standard order
  const sortedTactics = [...data.tactics].sort((a, b) => {
    const aIndex = TACTIC_ORDER.indexOf(a);
    const bIndex = TACTIC_ORDER.indexOf(b);
    if (aIndex === -1 && bIndex === -1) return a.localeCompare(b);
    if (aIndex === -1) return 1;
    if (bIndex === -1) return -1;
    return aIndex - bIndex;
  });

  // Organize techniques by parent/child relationship
  const organizedTechniquesByTactic: Record<string, Array<TechniqueDetail & { subtechniques: TechniqueDetail[], aggregated_detection_count: number }>> = {};

  for (const tactic of sortedTactics) {
    const techniques = data.techniques_by_tactic[tactic] || [];
    const parentTechniques: Map<string, TechniqueDetail & { subtechniques: TechniqueDetail[], aggregated_detection_count: number }> = new Map();
    const orphanSubtechniques: TechniqueDetail[] = [];

    // First pass: identify parent techniques
    for (const tech of techniques) {
      if (!tech.is_subtechnique) {
        parentTechniques.set(tech.technique_id, { ...tech, tactic, subtechniques: [], aggregated_detection_count: tech.detection_count });
      }
    }

    // Second pass: attach sub-techniques to parents and aggregate counts
    for (const tech of techniques) {
      if (tech.is_subtechnique && tech.parent_technique_id) {
        const parent = parentTechniques.get(tech.parent_technique_id);
        if (parent) {
          parent.subtechniques.push({ ...tech, tactic });
          // Add sub-technique detection count to parent's aggregated count
          parent.aggregated_detection_count += tech.detection_count;
        } else {
          // If parent doesn't exist in this tactic, show as orphan
          orphanSubtechniques.push({ ...tech, tactic });
        }
      }
    }

    // Sort parent techniques and include orphan subtechniques
    organizedTechniquesByTactic[tactic] = [
      ...Array.from(parentTechniques.values()).sort((a, b) => a.technique_id.localeCompare(b.technique_id)),
      ...orphanSubtechniques.map(t => ({ ...t, subtechniques: [], aggregated_detection_count: t.detection_count }))
    ];
  }

  // Calculate stats per tactic
  const tacticStats = sortedTactics.map(tactic => {
    const techniques = data.techniques_by_tactic[tactic] || [];
    const covered = techniques.filter(t => t.detection_count > 0).length;
    const total = techniques.length;
    const totalDetections = techniques.reduce((sum, t) => sum + t.detection_count, 0);
    return { tactic, covered, total, totalDetections, percentage: total > 0 ? (covered / total) * 100 : 0 };
  });

  // Count parent and sub-techniques
  const parentTechniqueCount = allTechniques.filter(t => !t.is_subtechnique).length;
  const subTechniqueCount = allTechniques.filter(t => t.is_subtechnique).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-gray-900">ATT&CK Coverage Matrix</h1>
          <p className="text-sm sm:text-base text-gray-600">
            {data.covered_techniques} of {data.total_techniques} techniques covered ({data.coverage_percentage.toFixed(1)}%)
          </p>
          <p className="text-xs sm:text-sm text-gray-500">
            {parentTechniqueCount} parent techniques, {subTechniqueCount} sub-techniques
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 text-sm text-gray-600">
            <input
              type="checkbox"
              checked={showSubtechniques}
              onChange={(e) => setShowSubtechniques(e.target.checked)}
              className="rounded border-gray-300"
            />
            <span className="hidden sm:inline">Show sub-techniques</span>
            <span className="sm:hidden">Subs</span>
          </label>
          <div className="flex bg-gray-100 rounded-lg p-1">
            <button
              onClick={() => setViewMode('heatmap')}
              className={clsx(
                'px-2 sm:px-3 py-1 rounded text-sm font-medium transition-colors',
                viewMode === 'heatmap' ? 'bg-white shadow text-gray-900' : 'text-gray-600 hover:text-gray-900'
              )}
            >
              <Grid3X3 className="h-4 w-4 inline sm:mr-1" />
              <span className="hidden sm:inline">Matrix</span>
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={clsx(
                'px-2 sm:px-3 py-1 rounded text-sm font-medium transition-colors',
                viewMode === 'list' ? 'bg-white shadow text-gray-900' : 'text-gray-600 hover:text-gray-900'
              )}
            >
              <List className="h-4 w-4 inline sm:mr-1" />
              <span className="hidden sm:inline">List</span>
            </button>
          </div>
          <a
            href={exportsApi.getAttackCoverageCsv()}
            className="flex items-center gap-1 sm:gap-2 px-3 sm:px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
          >
            <Download className="h-4 w-4" />
            <span className="hidden sm:inline">Export</span>
          </a>
        </div>
      </div>

      {/* Coverage Summary Bar */}
      <div className="bg-white rounded-lg shadow p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-700">Overall Coverage</span>
          <span className="text-sm font-bold text-gray-900">{data.coverage_percentage.toFixed(1)}%</span>
        </div>
        <div className="h-4 bg-gray-200 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-green-400 to-green-600 rounded-full transition-all duration-500"
            style={{ width: `${data.coverage_percentage}%` }}
          />
        </div>
        <div className="mt-3 flex items-center justify-between text-xs text-gray-500">
          <span>{data.covered_techniques} covered</span>
          <span>{data.total_techniques - data.covered_techniques} uncovered</span>
        </div>
      </div>

      {/* Legend */}
      <div className="bg-white rounded-lg shadow p-3 sm:p-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2 sm:gap-4">
            <span className="text-xs sm:text-sm font-medium text-gray-700">Detection Count:</span>
            <div className="flex items-center gap-1">
              <div className="w-5 h-5 sm:w-6 sm:h-6 bg-gray-200 rounded" title="0 detections" />
              <div className="w-5 h-5 sm:w-6 sm:h-6 bg-red-300 rounded" title="1 detection" />
              <div className="w-5 h-5 sm:w-6 sm:h-6 bg-orange-300 rounded" title="2-3 detections" />
              <div className="w-5 h-5 sm:w-6 sm:h-6 bg-yellow-300 rounded" title="4-5 detections" />
              <div className="w-5 h-5 sm:w-6 sm:h-6 bg-lime-400 rounded" title="6+ detections" />
              <div className="w-5 h-5 sm:w-6 sm:h-6 bg-green-500 rounded" title="High coverage" />
            </div>
            <span className="text-xs text-gray-500">0 → {maxDetectionCount}+</span>
          </div>
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <Info className="h-4 w-4 flex-shrink-0" />
            <span className="hidden sm:inline">Click technique for details and detections</span>
            <span className="sm:hidden">Tap for details</span>
          </div>
        </div>
      </div>

      {viewMode === 'heatmap' ? (
        /* Heatmap Matrix View */
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="overflow-x-auto">
            <div className="min-w-max">
              {/* Tactic Headers */}
              <div className="flex border-b-2 border-gray-300">
                {sortedTactics.map((tactic) => {
                  const stats = tacticStats.find(s => s.tactic === tactic);
                  return (
                    <div
                      key={tactic}
                      className="flex-shrink-0 w-32 p-2 bg-gray-900 text-white"
                    >
                      <div className="text-xs font-bold text-center leading-tight">
                        {tactic.replace(/-/g, ' ').toUpperCase()}
                      </div>
                      <div className="text-xs text-center text-gray-300 mt-1">
                        {stats?.covered}/{stats?.total}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Technique Cells */}
              <div className="flex">
                {sortedTactics.map((tactic) => {
                  const organizedTechniques = organizedTechniquesByTactic[tactic] || [];
                  return (
                    <div key={tactic} className="flex-shrink-0 w-32 border-r border-gray-200 last:border-r-0">
                      {organizedTechniques.map((tech) => (
                        <div key={tech.technique_id}>
                          {/* Parent technique - uses aggregated count for coloring */}
                          <div
                            className={clsx(
                              'h-10 border-b border-gray-100 cursor-pointer transition-all duration-150',
                              'flex items-center px-1',
                              getHeatmapColor(tech.aggregated_detection_count, maxDetectionCount),
                              getHeatmapTextColor(tech.aggregated_detection_count, maxDetectionCount),
                              'hover:ring-2 hover:ring-blue-500 hover:ring-inset hover:z-10',
                              selectedTechnique?.technique_id === tech.technique_id && 'ring-2 ring-blue-600 ring-inset'
                            )}
                            onClick={() => handleTechniqueClick({ ...tech, tactic })}
                            onMouseEnter={() => setHoveredTechnique({ ...tech, tactic, detection_count: tech.aggregated_detection_count })}
                            onMouseLeave={() => setHoveredTechnique(null)}
                            title={`${tech.technique_id}: ${tech.technique_name} (${tech.aggregated_detection_count} total detections${tech.subtechniques.length > 0 ? `, ${tech.detection_count} direct` : ''})`}
                          >
                            {/* Expand/collapse button for techniques with sub-techniques */}
                            {showSubtechniques && tech.subtechniques.length > 0 && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleTechniqueExpand(tech.technique_id);
                                }}
                                className="mr-1 hover:bg-black/10 rounded"
                              >
                                {expandedTechniques.has(tech.technique_id) ? (
                                  <ChevronDown className="h-3 w-3" />
                                ) : (
                                  <ChevronRight className="h-3 w-3" />
                                )}
                              </button>
                            )}
                            <span className="text-xs font-medium truncate flex-1">
                              {tech.technique_id.replace('T', '')}
                            </span>
                            {tech.subtechniques.length > 0 && (
                              <span className="text-[10px] opacity-70">
                                +{tech.subtechniques.length}
                              </span>
                            )}
                          </div>

                          {/* Sub-techniques (when expanded) */}
                          {showSubtechniques && expandedTechniques.has(tech.technique_id) && tech.subtechniques.map((sub) => (
                            <div
                              key={sub.technique_id}
                              className={clsx(
                                'h-8 border-b border-gray-100 cursor-pointer transition-all duration-150',
                                'flex items-center pl-4 pr-1',
                                getHeatmapColor(sub.detection_count, maxDetectionCount),
                                getHeatmapTextColor(sub.detection_count, maxDetectionCount),
                                'hover:ring-2 hover:ring-blue-500 hover:ring-inset hover:z-10',
                                selectedTechnique?.technique_id === sub.technique_id && 'ring-2 ring-blue-600 ring-inset'
                              )}
                              onClick={() => handleTechniqueClick(sub)}
                              onMouseEnter={() => setHoveredTechnique(sub)}
                              onMouseLeave={() => setHoveredTechnique(null)}
                              title={`${sub.technique_id}: ${sub.technique_name} (${sub.detection_count} detections)`}
                            >
                              <span className="text-[10px] font-medium truncate">
                                .{sub.technique_id.split('.')[1]}
                              </span>
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Hover/Selected Technique Info Panel */}
          {(hoveredTechnique || selectedTechnique) && !modalData && (
            <div className="border-t border-gray-200 p-4 bg-gray-50">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-gray-900">
                      {(hoveredTechnique || selectedTechnique)?.technique_id}
                    </span>
                    {(hoveredTechnique || selectedTechnique)?.is_subtechnique && (
                      <span className="px-2 py-0.5 text-xs font-medium rounded bg-purple-100 text-purple-800">
                        Sub-technique
                      </span>
                    )}
                    <span className={clsx(
                      'px-2 py-0.5 text-xs font-medium rounded',
                      (hoveredTechnique || selectedTechnique)?.detection_count === 0
                        ? 'bg-gray-200 text-gray-600'
                        : 'bg-green-100 text-green-800'
                    )}>
                      {(hoveredTechnique || selectedTechnique)?.detection_count} detection(s)
                    </span>
                  </div>
                  <p className="text-gray-700 mt-1">
                    {(hoveredTechnique || selectedTechnique)?.technique_name}
                  </p>
                  <p className="text-sm text-gray-500 mt-1">
                    Tactic: {(hoveredTechnique || selectedTechnique)?.tactic.replace(/-/g, ' ')}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {(hoveredTechnique || selectedTechnique)?.url && (
                    <a
                      href={(hoveredTechnique || selectedTechnique)?.url || undefined}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:text-blue-800 flex items-center gap-1 text-sm"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <ExternalLink className="h-4 w-4" />
                      MITRE ATT&CK
                    </a>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      ) : (
        /* List View */
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Top Covered Techniques</h2>
            <div className="space-y-2">
              {data.top_covered.slice(0, 15).map((tech) => (
                <div
                  key={tech.technique_id}
                  className="flex items-center justify-between hover:bg-gray-50 p-2 rounded cursor-pointer"
                  onClick={() => handleTechniqueClick({ ...tech, tactic: tech.tactics[0] || '' })}
                >
                  <div className="flex-1 min-w-0">
                    <span className="font-medium">{tech.technique_id}</span>
                    {tech.is_subtechnique && (
                      <span className="ml-1 text-xs text-purple-600">(sub)</span>
                    )}
                    <span className="text-gray-500 ml-2 truncate">{tech.technique_name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="ml-2 px-2 py-1 bg-green-100 text-green-800 text-sm rounded whitespace-nowrap">
                      {tech.detection_count} detections
                    </span>
                    <a
                      href={tech.url || undefined}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-400 hover:text-blue-600"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Uncovered Techniques</h2>
            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {data.uncovered.slice(0, 30).map((tech) => (
                <div key={tech.technique_id} className="flex items-center justify-between text-sm p-2 hover:bg-gray-50 rounded">
                  <div className="flex-1 min-w-0">
                    <span className="font-medium">{tech.technique_id}</span>
                    <span className="text-gray-500 ml-2 truncate">{tech.technique_name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="ml-2 px-2 py-1 bg-red-100 text-red-800 rounded whitespace-nowrap">
                      No coverage
                    </span>
                    <a
                      href={`https://attack.mitre.org/techniques/${tech.technique_id.replace('.', '/')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-400 hover:text-blue-600"
                    >
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tactic Summary Cards */}
      <div className="bg-white rounded-lg shadow p-4 sm:p-6">
        <h2 className="text-base sm:text-lg font-semibold text-gray-900 mb-4">Coverage by Tactic</h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-2 sm:gap-3">
          {tacticStats.map(({ tactic, covered, total, percentage, totalDetections }) => (
            <div
              key={tactic}
              className="p-2 sm:p-3 rounded-lg bg-gray-50 hover:bg-gray-100 transition-colors"
            >
              <div className="text-[10px] sm:text-xs font-medium text-gray-500 uppercase truncate" title={tactic}>
                {tactic.replace(/-/g, ' ')}
              </div>
              <div className="mt-1 flex items-end justify-between">
                <span className="text-lg sm:text-2xl font-bold text-gray-900">
                  {percentage.toFixed(0)}%
                </span>
                <span className="text-[10px] sm:text-xs text-gray-500">
                  {covered}/{total}
                </span>
              </div>
              <div className="mt-2 h-1 sm:h-1.5 bg-gray-200 rounded-full overflow-hidden">
                <div
                  className={clsx(
                    'h-full rounded-full transition-all',
                    percentage >= 70 ? 'bg-green-500' :
                    percentage >= 40 ? 'bg-yellow-500' :
                    percentage > 0 ? 'bg-red-400' : 'bg-gray-300'
                  )}
                  style={{ width: `${percentage}%` }}
                />
              </div>
              <div className="mt-1 text-[10px] sm:text-xs text-gray-400">
                {totalDetections} detection{totalDetections !== 1 ? 's' : ''}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technique Details Modal */}
      {(modalData || isModalLoading) && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-2xl max-w-2xl w-full max-h-[80vh] overflow-hidden">
            {isModalLoading ? (
              <div className="p-8 flex items-center justify-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
              </div>
            ) : modalData && (
              <>
                <div className="p-6 border-b border-gray-200">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="text-xl font-bold text-gray-900">{modalData.technique_id}</h2>
                        {modalData.is_subtechnique && (
                          <span className="px-2 py-0.5 text-xs font-medium rounded bg-purple-100 text-purple-800">
                            Sub-technique of {modalData.parent_technique_id}
                          </span>
                        )}
                      </div>
                      <p className="text-gray-700 mt-1">{modalData.technique_name}</p>
                      <div className="flex items-center gap-2 mt-2">
                        {modalData.tactics.map(t => (
                          <span key={t} className="px-2 py-0.5 text-xs font-medium rounded bg-gray-100 text-gray-700">
                            {t.replace(/-/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <a
                        href={modalData.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:text-blue-800 flex items-center gap-1 text-sm px-3 py-1 border border-blue-200 rounded-lg hover:bg-blue-50"
                      >
                        <ExternalLink className="h-4 w-4" />
                        View in ATT&CK
                      </a>
                      <button
                        onClick={closeModal}
                        className="text-gray-400 hover:text-gray-600"
                      >
                        <X className="h-6 w-6" />
                      </button>
                    </div>
                  </div>
                </div>

                <div className="p-6 overflow-y-auto max-h-[60vh]">
                  {/* Sub-techniques section */}
                  {modalData.subtechniques.length > 0 && (
                    <div className="mb-6">
                      <h3 className="text-sm font-semibold text-gray-900 mb-3">
                        Sub-techniques ({modalData.subtechniques.length})
                      </h3>
                      <div className="space-y-2">
                        {modalData.subtechniques.map(sub => (
                          <div
                            key={sub.technique_id}
                            className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer"
                            onClick={() => handleTechniqueClick({
                              technique_id: sub.technique_id,
                              technique_name: sub.technique_name,
                              detection_count: sub.detection_count,
                              tactic: modalData.tactics[0] || '',
                              is_subtechnique: true,
                              parent_technique_id: modalData.technique_id,
                              url: sub.url,
                            })}
                          >
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-sm">{sub.technique_id}</span>
                              <span className="text-gray-600 text-sm">{sub.technique_name}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className={clsx(
                                'px-2 py-0.5 text-xs font-medium rounded',
                                sub.detection_count > 0 ? 'bg-green-100 text-green-800' : 'bg-gray-200 text-gray-600'
                              )}>
                                {sub.detection_count} detection(s)
                              </span>
                              <a
                                href={sub.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-gray-400 hover:text-blue-600"
                                onClick={(e) => e.stopPropagation()}
                              >
                                <ExternalLink className="h-4 w-4" />
                              </a>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Detections section */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 mb-3">
                      Mapped Detections ({modalData.detection_count})
                    </h3>
                    {modalData.detections.length === 0 ? (
                      <div className="flex items-center gap-2 p-4 bg-yellow-50 text-yellow-800 rounded-lg">
                        <AlertCircle className="h-5 w-5" />
                        <span>No detections currently mapped to this technique.</span>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {modalData.detections.map(det => (
                          <div key={det.id} className="p-4 border border-gray-200 rounded-lg hover:border-blue-300">
                            <div className="flex items-start justify-between">
                              <div>
                                <div className="flex items-center gap-2">
                                  <a
                                    href={`/detections/${det.id}`}
                                    className="font-medium text-blue-600 hover:text-blue-800"
                                  >
                                    {det.name}
                                  </a>
                                  <span className={clsx(
                                    'px-2 py-0.5 text-xs font-medium rounded',
                                    det.severity === 'critical' ? 'bg-red-100 text-red-800' :
                                    det.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                                    det.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                                    'bg-blue-100 text-blue-800'
                                  )}>
                                    {det.severity}
                                  </span>
                                  <span className={clsx(
                                    'px-2 py-0.5 text-xs font-medium rounded',
                                    det.status === 'enabled' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'
                                  )}>
                                    {det.status}
                                  </span>
                                </div>
                                <p className="text-sm text-gray-500 mt-1">{det.detection_id}</p>
                              </div>
                              <div className="text-right">
                                <div className="text-sm font-medium text-gray-700">
                                  {(det.confidence * 100).toFixed(0)}% confidence
                                </div>
                                <div className="text-xs text-gray-500">
                                  via {det.method}
                                </div>
                              </div>
                            </div>
                            {det.rationale && (
                              <p className="mt-2 text-sm text-gray-600 bg-gray-50 p-2 rounded">
                                {det.rationale}
                              </p>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
